from flask import Flask, render_template, make_response, request
import operator as op
import re

app = Flask(__name__)
application = app

# OPERATIONS = {
#     '+': lambda x, y: x + y,
#     '-': lambda x, y: x - y,
#     '*': lambda x, y: x * y,
#     '/': lambda x, y: x / y

OPERATIONS = { '+': op.add, '-': op.sub, '*': op.mul,  '/': op.truediv }


@app.route('/')
def index():
    url = request.url
    return render_template('index.html', url=url)


@app.route('/args')
def args():
    return render_template('args.html')


@app.route('/headers')
def headers():
    return render_template('headers.html')


@app.route('/cookies')
def cookies():
    response = make_response(render_template('cookies.html'))
    if 'biscuit' in request.cookies:
        response.delete_cookie('biscuit')
    else:
        response.set_cookie('biscuit', value='100 gramm')
    return response


@app.route('/form', methods=['GET', 'POST'])
def form():
    return render_template('form.html')

# зачем r (82 строка), make_response (35 строка), get и post (43 строка)
@app.route('/calculator', methods=['GET', 'POST'])
def calculator():
    result = ''
    error = ''
    if request.method == 'POST':
        try:
            operation = request.form.get('operation')
            oper1 = int(request.form.get('oper1'))
            oper2 = int(request.form.get('oper2'))

            result = OPERATIONS[operation](oper1, oper2)
        except ValueError:
            error = 'Со строками нельзя проводить математические операции!'
        except ZeroDivisionError:
            error = 'На ноль делить нельзя!!!'
        except KeyError:
            error = 'Неизвестная математическая операция :('

    return render_template('calculator.html', result=result, error=error, operations=OPERATIONS.keys())


@app.route('/validation-phone', methods=['GET', 'POST'])
def validate_phone_number():
    phone = request.form.get('phone')
    error = None

    if not phone:
        error = 'Вы не ввели номер телефона!'
    elif not all(char.isdigit() or char in '()+-. ' for char in phone):
        error = 'Недопустимые символы в номере телефона!'
    elif len(''.join(filter(str.isdigit, phone))) not in (10, 11):
        error = 'Неверное количество цифр в номере телефона!'

    if not error:
        digits = re.sub(r'\D', '', phone)  # r'\D' регулярное выражение, которое соответствует любому символу, который не является цифрой
        formatted_phone = '8-{}-{}-{}-{}'.format(digits[:3], digits[3:6], digits[6:8], digits[8:]) 
        error = f'Вы ввели корректный номер телефона. Спасибо. Преобразованный номер: {formatted_phone}'

    return render_template('validation-phone.html', error=error)


