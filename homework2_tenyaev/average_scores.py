def compute_average_scores(scores):
    averages = []
    for student_scores in zip(*scores):
        average_score = sum(student_scores) / len(student_scores)
        averages.append(round(average_score, 1))
    return tuple(averages)

if __name__ == "__main__":
    N, X = map(int, input().split())
    scores = [tuple(map(float, input().split())) for _ in range(X)]
    for average_score in compute_average_scores(scores):
        print(average_score)
