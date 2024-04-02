import os

def find_file(file_name):
    directory = os.path.dirname(os.path.abspath(__file__))
    for root, dirs, files in os.walk(directory):
        if file_name in files:
            file_path = os.path.join(root, file_name)
            with open(file_path, 'r') as file:
                print(f"Файл {file_name} найден. Первые 5 строк: ")
                for i in range(5):
                    line = file.readline().strip()
                    print(line)
            return
    print(f"File {file_name} not found.")

if __name__ == '__main__':
    file_name = input("Введите имя файла: ")
    find_file(file_name)

