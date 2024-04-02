import subprocess
import pytest
import math
INTERPRETER = 'python'

def run_script(filename, input_data=None):
    proc = subprocess.run(
        [INTERPRETER, filename],
        input='\n'.join(input_data if input_data else []),
        capture_output=True,
        text=True,
        check=False
    )
    return proc.stdout.strip()

test_data = {
    'fact': [
        (5, 120)
    ],
    'show_employee': [
        (['Теняев Виктор Сергеевич', '5000'], 'Теняев Виктор Сергеевич: 5000.0 ₽'),
        (['Дерехов Дмитрий Иванович', '0'], 'Дерехов Дмитрий Иванович: 0.0 ₽'),
        (['Петров Пётр Петрович', '2000'], 'Петров Пётр Петрович: 2000.0 ₽'),
        (['Сидорова Анна Ивановна', ''], 'Сидорова Анна Ивановна: 100000 ₽'),
        (['Смирнов Сергей Павлович', '0'], 'Смирнов Сергей Павлович: 0.0 ₽')
    ],
    'sum_and_sub': [
        ([5, 5], [10.0, 0.0]),
        ([-5, -3], [-8.0, -2.0]),
        ([10, -3], [7.0, 13.0]),
        ([3.5, 2.5], [6.0, 1.0]),
        ([0, 7], [7.0, -7.0])
    ],
    'process_list_comprehension': [
        ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], [1, 4, 27, 16, 125, 36, 343, 64, 729, 100]),
        ([10, 9, 8, 7, 6, 5, 4, 3, 2, 1], [100, 729, 64, 343, 36, 125, 16, 27, 4, 1]),
        ([], []),
        ([0, 0, 0, 0, 0], [0, 0, 0, 0, 0]),
        ([2, 4, 6, 8, 10], [4, 16, 36, 64, 100]),
        ([1, 3, 5, 7, 9], [1, 27, 125, 343, 729]),
    ],
    'my_sum': [
        ([1, 2, 3], 6),
        ([-1, -2, -3], -6),
        ([10.5, 20.5, 30.5], 61.5),
        ([-10.5, 20.5, -30.5], -20.5),
        ([0], 0),
        ([], 0), 
    ],
    'fun':[
        ("lara@mospolytech.ru", True),
        ("brian-23@mospolytech.ru", True),
        ("britts_54@mospolytech.ru", True),
        ("invalid.email", False),
        ("invalid@.com", False),
        ("@invalid.com", False),
        ("invalid.com", False),
        ("invalid@com", False),
        ("invalid@com.", False),
        ("invalid@com..", False),
        ("invalid@com...", False),
        ("invalid-email@com", False),
        ("invalid.email@com", False),
        ("invalid.email@com.", False),
        ("invalid.email@com..", False),
        ("invalid.email@com...", False),        
    ],
    'fibonacci':[
        (0, []),
        (1, [0]),
        (2, [0, 1]),
        (3, [0, 1, 1]),
        (5, [0, 1, 1, 2, 3]),
        (8, [0, 1, 1, 2, 3, 5, 8, 13]),
        (10, [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]),
        (15, [0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377]),
    ],
    'compute_average_scores': [
        ([(89, 90, 78, 93, 80), (90, 91, 85, 88, 86), (91, 92, 83, 89, 90.5)], (90.0, 91.0, 82.0, 90.0, 85.5)),
        ([(70, 80, 90), (75, 85, 95), (80, 90, 100)], (75.0, 85.0, 95.0)),
        ([(100, 0, 50), (90, 100, 80), (80, 70, 60)], (90.0, 56.7, 63.3)),
        ([(85, 90, 95), (95, 90, 85), (80, 85, 90)], (86.7, 88.3, 90.0)),
        ([(100, 100, 100), (90, 90, 90), (80, 80, 80)], (90.0, 90.0, 90.0)),
        ([(0, 0, 0), (0, 0, 0), (0, 0, 0)], (0.0, 0.0, 0.0))
    ],

    'name_format':[
        (["Mike", "Thomson", "20", "M"], "Mr. Mike Thomson"),
        (["Robert", "Bustle", "32", "M"], "Mr. Robert Bustle"),
        (["Andria", "Bustle", "30", "F"], "Ms. Andria Bustle"),
        (["Alice", "Wonderland", "25", "F"], "Ms. Alice Wonderland"),
        (["John", "Doe", "40", "M"], "Mr. John Doe"),
        (["Emily", "Smith", "18", "F"], "Ms. Emily Smith"),
        (["Jack", "Johnson", "50", "M"], "Mr. Jack Johnson"),
        (["Jane", "Doe", "70", "F"], "Ms. Jane Doe"),
    ],
}

from fact import fact_it
from show_employee import show_employee
from sum_and_sub import sum_and_sub
from process_list import process_list_comprehension
from my_sum import my_sum
from email_validation import fun
from fibonacci import fibonacci
from average_scores import compute_average_scores
from phone_number import sort_phone
from people_sort import name_format

@pytest.mark.parametrize("input_data, expected", test_data['fact'])
def test_fact(input_data, expected):
    assert fact_it(input_data) == expected

@pytest.mark.parametrize("input_data, expected", test_data['show_employee'])
def test_show_employee(input_data, expected):
    assert show_employee(*input_data) == expected

@pytest.mark.parametrize("input_data, expected", test_data['sum_and_sub'])
def test_sum_and_sub(input_data, expected):
    assert sum_and_sub(input_data) == expected

@pytest.mark.parametrize("input_data, expected", test_data['process_list_comprehension'])
def test_process_list_comprehension(input_data, expected):
    assert process_list_comprehension(input_data) == expected

@pytest.mark.parametrize("input_data, expected", test_data['my_sum'])
def test_my_sum(input_data, expected):
    assert my_sum(*input_data) == expected

@pytest.mark.parametrize("input_data, expected", test_data['fun'])
def test_fun(input_data, expected):
    assert fun(input_data) == expected

@pytest.mark.parametrize("input_data, expected", test_data['fibonacci'])
def test_fibonacci(input_data, expected):
    assert fibonacci(input_data) == expected

@pytest.mark.parametrize("input_data, expected", test_data['compute_average_scores'])
def test_compute_average_scores(input_data, expected):
    assert compute_average_scores(input_data) == expected

@pytest.mark.parametrize("input_data, expected", test_data['name_format'])
def test_name_format(input_data, expected):
    assert name_format(input_data) == expected

