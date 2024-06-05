import os

SECRET_KEY = '1fdf45545a89b94b956eee6ec780ecc7adf2baf4eddb8163e60b6d18c2f48adc'
# SECRET_KEY = os.environ.get('SECRET_KEY')

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, 'app.db')