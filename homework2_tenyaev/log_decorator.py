import datetime

def function_logger(log_file):
    def decorator(func):
        def wrapper(*args, **kwargs):
            with open(log_file, 'a+') as f:
                f.write(f"{func.__name__}\n")
                start_time = datetime.datetime.now()
                f.write(f"{start_time}\n")
                f.write(f"{args, kwargs}\n")
                result = func(*args, **kwargs)
                f.write(f"{result if result is not None else '-'}\n")
                end_time = datetime.datetime.now()
                f.write(f"{end_time}\n")
                elapsed_time = end_time - start_time
                f.write(f"{elapsed_time}\n\n")
            return result
        return wrapper
    return decorator

@function_logger('log_dec.log')
def greeting_format(name):
    return f'Hello, {name}!'

greeting_format('Victor')
