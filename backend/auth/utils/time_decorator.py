import os
from pathlib import Path
import time
import functools
from datetime import datetime
import contextvars

# Переменная для хранения уровня вложенности
indent_var = contextvars.ContextVar("indent", default=0)

# Настройка путей
base_path = Path(__file__).parent.parent
full_path_dir = f"{base_path}/reports"


def time_all_methods(decorator):
    """Декоратор класса: применяет указанный декоратор ко всем методам."""
    def decorate(cls):
        for attr in cls.__dict__:
            if callable(getattr(cls, attr)) and not attr.startswith("__"):
                setattr(cls, attr, decorator(getattr(cls, attr)))
        return cls
    return decorate


def async_timed_report():
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            indent = indent_var.get()
            indent_var.set(indent + 1) # Увеличиваем отступ для вложенных функций
            
            start_time = time.perf_counter()
            try:
                return await func(*args, **kwargs)
            finally:
                end_time = time.perf_counter()
                duration = end_time - start_time
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                report_line = (f"[{timestamp}] Функция: {func.__name__} | "
                               f"Время выполнения: {duration:.4f} сек.\n")
                
                with open(os.path.join(full_path_dir, "async_timed_report.txt"), "a", encoding="utf-8") as f:
                    f.write(report_line)
                indent_var.set(indent) # Возвращаем уровень назад
        return wrapper
    return decorator

def sync_timed_report():
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            indent = indent_var.get()
            indent_var.set(indent + 1) # Увеличиваем отступ для вложенных функций
            
            start_time = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                end_time = time.perf_counter()
                duration = end_time - start_time
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                report_line = (f"[{timestamp}] Функция: {func.__name__} | "
                               f"Время выполнения: {duration:.4f} сек.\n")
                
                with open(os.path.join(full_path_dir, "sync_timed_report.txt"), "a", encoding="utf-8") as f:
                    f.write(report_line)
                indent_var.set(indent) # Возвращаем уровень назад
        return wrapper
    return decorator

if __name__ == "__main__":
    @sync_timed_report()
    def heavy_computation():
        print("Выполняю сложные расчеты...")
        time.sleep(1.2)
        return "Расчет окончен"

    res = heavy_computation()
    print(res)
