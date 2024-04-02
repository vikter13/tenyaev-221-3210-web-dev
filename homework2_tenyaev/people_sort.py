import operator

def person_lister(f):
    def inner(people):
        sorted_people = sorted(people, key=operator.itemgetter(2))
        formatted_names = [f(person) for person in sorted_people]
        return formatted_names
    return inner

def name_format(person):
    prefix = "Mr. " if person[3] == "M" else "Ms. "
    formatted_name = prefix + person[0] + " " + person[1]
    return formatted_name

if __name__ == '__main__':
    n = int(input())
    people = [input().split() for _ in range(n)]
    result = person_lister(name_format)(people)
    print(*result, sep='\n')
