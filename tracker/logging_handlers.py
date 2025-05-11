import logging
import traceback  # To format traceback information

# Ensure your CriticalErrorLog model is accessible.
# Adjust the import path if your models.py is structured differently
# or if you place this handler in a different app.



class DatabaseLogHandler(logging.Handler):
    """
    A custom logging handler that writes log records (especially critical errors)
    to the CriticalErrorLog model in the database.
    """

    def __init__(self, level=logging.NOTSET):
        super().__init__(level=level)

    def emit(self, record: logging.LogRecord): # Added type hint for clarity
        """
        This method is called when a log record needs to be processed.
        It creates and saves a CriticalErrorLog instance.
        """
        # Import the model here if preferred, to avoid issues with app loading order.
        from .models import CriticalErrorLog

        try:
            # Prepare traceback information if available
            tb_str = None
            if record.exc_info:
                # Ensure exc_info is a 3-tuple (type, value, traceback) or True
                if isinstance(record.exc_info, tuple) and len(record.exc_info) == 3:
                    tb_str = "".join(traceback.format_exception(record.exc_info[0], record.exc_info[1], record.exc_info[2]))
                elif record.exc_info is True: # Indicates sys.exc_info() should be used
                    exc_type, exc_value, exc_tb = logging.sys.exc_info()
                    if exc_type: # If an exception actually occurred
                        tb_str = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
            elif hasattr(record, 'stack_info') and record.stack_info:
                tb_str = self.formatStack(record.stack_info)


            # Use record.getMessage() for the fully formatted message.
            # self.format(record) could also work but getMessage() is more direct for the message part.
            formatted_message = record.getMessage()
            if hasattr(record, 'exc_text') and record.exc_text: # If there's pre-formatted exception text, append it.
                formatted_message += "\n" + record.exc_text


            # Map LogRecord attributes to CriticalErrorLog model fields
            log_data = {
                'level': record.levelname,
                'module': record.pathname,  # Use record.pathname for the module/file path
                'function': record.funcName,
                'line_number': record.lineno,
                'message': formatted_message,
                'traceback': tb_str if tb_str else "", # Ensure it's not None
                # 'timestamp' is auto_now_add=True in the model
                # 'acknowledged' fields are handled by their defaults or application logic
            }

            CriticalErrorLog.objects.create(**log_data)

        except Exception as e: # Catch specific exceptions if possible, e.g., DatabaseError
            # Handle any exception during the logging process itself
            # (e.g., database connection error) to prevent a loop.
            # You might want to log this to a fallback logger or print to stderr.
            self.handleError(record) # Default behavior often prints to stderr
            # For more explicit debugging during this phase:
            # import sys
            # print(f"--- ERROR IN DB HANDLER: Failed to log to database: {e} ---", file=sys.stderr)
            # print(f"--- Original Log Record: {record.__dict__} ---", file=sys.stderr)
            # print(f"--- Mapped Log Data: {log_data if 'log_data' in locals() else 'N/A'} ---", file=sys.stderr)
            # if record.exc_info:
            #     traceback.print_exc(file=sys.stderr)
            # print("--- END DB LOGGING ERROR ---", file=sys.stderr)

    def formatStack(self, stack_info): # Helper from logging.Formatter if you use stack_info
        """
        Format an exception stack.
        """
        return ''.join(traceback.format_stack(f=stack_info))
