def show_employee(name : str, salary : int = 100000) -> str:
    return f"{name}: {salary} ₽"

if __name__ == "__main__":
    name = input("Enter the employee's name: ")
    salary = input("Specify the employee's salary: ")
    if (salary):
        print(show_employee(name, int(salary)))
    else:
        print(show_employee(name))