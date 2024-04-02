import random
import math

def circle_square_mk(r, n):
    inside_circle = 0

    for _ in range(n):
        x = random.uniform(-r, r)
        y = random.uniform(-r, r)
        if x**2 + y**2 <= r**2:
            inside_circle += 1

    square = (inside_circle / n) * (4 * r**2)
    return square

if __name__ == "__main__":
    r = 1
    n_values = [100, 1000, 1234]
    for n in n_values:
        square = circle_square_mk(r, n)
        print(f"Площадь окружности при n = {n}: {square}")

# Площадь окружности при n = 100: 3.08
# Площадь окружности при n = 1000: 3.16
# Площадь окружности при n = 1234: 3.1442463533225284