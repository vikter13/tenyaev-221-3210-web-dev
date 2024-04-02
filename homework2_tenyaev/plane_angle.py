import math


class Point:
    def __init__(self, x, y, z):
        self.x = x
        self.y = y
        self.z = z

    def __sub__(self, no):
        return Point(self.x - no.x, self.y - no.y, self.z - no.z)

    def dot(self, no):
        return self.x * no.x + self.y * no.y + self.z * no.z

    def cross(self, no):
        return Point(self.y * no.z - self.z * no.y, self.z * no.x - self.x * no.z, self.x * no.y - self.y * no.x)

    def absolute(self):
        return math.sqrt(self.x ** 2 + self.y ** 2 + self.z ** 2)


def plane_angle(a, b, c, d):
    AB = b - a
    BC = c - b
    CD = d - c

    X = AB.cross(BC)
    Y = BC.cross(CD)

    cos_phi = X.dot(Y) / (X.absolute() * Y.absolute())
    phi_rad = math.acos(cos_phi)
    phi_deg = math.degrees(phi_rad)

    return phi_deg


if __name__ == '__main__':
    x1, y1, z1 = map(float, input().split())
    x2, y2, z2 = map(float, input().split())
    x3, y3, z3 = map(float, input().split())
    x4, y4, z4 = map(float, input().split())

    A = Point(x1, y1, z1)
    B = Point(x2, y2, z2)
    C = Point(x3, y3, z3)
    D = Point(x4, y4, z4)

    result = plane_angle(A, B, C, D)
    print("{:.2f}".format(result))
