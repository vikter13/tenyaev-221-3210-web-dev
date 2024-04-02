import sys

def my_sum(*args):
    return sum(args)

if __name__ == '__main__':
    numbers = [float(num) for num in sys.argv[1:]]
    result = my_sum(*numbers)
    print(result)
