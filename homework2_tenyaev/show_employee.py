def show_employee(name, salary_input):
    if salary_input:
        salary = float(salary_input)
    else:
        salary = 100000
    return f"{name}: {salary} ₽"

if __name__ == "__main__":
    print(show_employee())
