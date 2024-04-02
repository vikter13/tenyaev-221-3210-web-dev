def sum_and_sub(input_data):
    a, b = map(float, input_data)
    sum_result = a + b
    sub_result = a - b
    return [sum_result, sub_result]


if __name__ == "__main__":
    result_sum, result_sub = sum_and_sub()
    print(result_sum)
    print(result_sub)
