def process_list_comprehension(arr):
    return [i**2 if i % 2 == 0 else i**3 for i in arr]

def process_list_gen(arr):
    for i in arr:
        yield i**2 if i % 2 == 0 else i**3

if __name__ == '__main__':
    arr = []

    result_comprehension = process_list_comprehension(arr)
    print("List comprehension:", result_comprehension)

    result_gen = list(process_list_gen(arr))
    print("Generator function:", result_gen)
