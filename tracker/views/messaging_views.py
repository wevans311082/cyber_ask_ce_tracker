from django.db.models import Q  # Q object for complex lookups
from django.views.generic import DetailView
from django.shortcuts import redirect, get_object_or_404
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.contrib import messages  # Optional: for user feedback
from django.utils import timezone  # Optional: for logging or advanced logic
import logging

from tracker.models import *
from tracker.forms import *
from tracker.mixin import *

logger = logging.getLogger(__name__)  # Make sure logging is imported if you use logger


class ConversationParticipantRequiredMixin(LoginRequiredMixin):
    # ... (as defined before) ...
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)


class ConversationDetailView(ConversationParticipantRequiredMixin, DetailView):
    model = Conversation
    template_name = 'tracker/client/conversation_detail.html'
    context_object_name = 'conversation'

    def get_queryset(self):
        return Conversation.objects.filter(
            Q(client=self.request.user) | Q(assessor=self.request.user)
        ).select_related('assessment', 'client__userprofile', 'assessor__userprofile')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        conversation = self.object
        current_user = self.request.user

        # Mark unread messages as read for the current user
        unread_messages = conversation.messages.exclude(read_by=current_user)
        messages_marked_read_count = 0
        for msg in unread_messages:
            if msg.mark_as_read(current_user):
                messages_marked_read_count += 1

        if messages_marked_read_count > 0:
            logger.info(
                f"User {current_user.username} marked {messages_marked_read_count} messages as read in conversation {conversation.pk}")

        context['form'] = MessageForm()

        # CHANGES BEGIN — 2025-05-22 22:20:00
        # Prepare messages_list with read receipt info
        messages_from_db = conversation.messages.select_related('sender__userprofile').prefetch_related('read_by').all()
        processed_messages_list = []
        other_participant = conversation.get_other_participant(current_user)

        for msg in messages_from_db:
            msg.is_read_by_recipient = False  # Default
            if msg.sender == current_user and other_participant:
                if other_participant in msg.read_by.all():
                    msg.is_read_by_recipient = True
            processed_messages_list.append(msg)

        context['messages_list'] = processed_messages_list
        # CHANGES END — 2025-05-22 22:20:00
        return context

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        form = MessageForm(request.POST)

        if form.is_valid():
            message_instance = form.save(commit=False)
            message_instance.conversation = self.object
            message_instance.sender = request.user
            message_instance.save()

            message_instance.mark_as_read(request.user)

            self.object.updated_at = timezone.now()
            self.object.save(update_fields=['updated_at'])

            logger.info(f"User {request.user.username} sent message in conversation {self.object.pk}")
            return redirect('tracker:conversation_detail', pk=self.object.pk)
        else:
            logger.warning(
                f"Invalid message form submission by {request.user.username} for conversation {self.object.pk}")
            context = self.get_context_data()
            context['form'] = form
            return self.render_to_response(context)