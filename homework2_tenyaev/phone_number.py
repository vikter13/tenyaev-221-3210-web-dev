def wrapper(f):
    def fun(l):
        def format_phone_number(phone):
            phone = ''.join(filter(str.isdigit, phone))

            if phone.startswith('8') or phone.startswith('9'):
                phone = '7' + phone[1:]

            formatted_phone = '+7 ({}) {}-{}-{}'.format(phone[1:4], phone[4:7], phone[7:9], phone[9:11])

            return formatted_phone

        return [format_phone_number(phone) for phone in f(l)]
    return fun

@wrapper
def sort_phone(l):
    return sorted(l)

if __name__ == '__main__':
    l = [input() for _ in range(int(input()))]
    print(*sort_phone(l), sep='\n')
