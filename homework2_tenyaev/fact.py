import time

def fact_rec(n):
    if n == 0 or n == 1:
        return 1
    else:
        return n * fact_rec(n - 1)

def fact_it(n):
    result = 1
    for i in range(1, n + 1):
        result *= i
    return result

if __name__ == "__main__":
    n = int(input())

    start_time_rec = time.time()
    fact_rec(n)
    end_time_rec = time.time()

    start_time_it = time.time()
    fact_it(n)
    end_time_it = time.time()

    print(end_time_rec - start_time_rec, end_time_it - start_time_it)
