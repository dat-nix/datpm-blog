#!/usr/bin/env python3

OLD_FIRST_HALF = [
    (0, 247, 40, 120),
    (1, 195, 0, 68),
    (2, 89, 105, 45),
    (3, 77, 179, 70),
    (4, 107, 221, 62),
    (5, 37, 117, 101),
    (6, 11, 232, 52),
    (7, 205, 46, 5),
    (8, 93, 161, 36),
    (9, 47, 220, 181),
    (10, 195, 222, 49),
    (11, 191, 233, 251),
    (12, 69, 35, 108),
]

NEW_SECOND_HALF = [
    (13, 87, 33, 108),
    (14, 233, 61, 201),
    (15, 197, 97, 245),
    (16, 155, 124, 72),
    (17, 75, 219, 93),
    (18, 115, 213, 5),
    (19, 219, 87, 227),
    (20, 221, 230, 166),
    (21, 69, 83, 123),
    (22, 139, 156, 253),
    (23, 193, 229, 111),
    (24, 93, 241, 181),
]

OLD_MASK = [114, 157, 234, 123, 50, 120, 87, 159, 59, 45, 110, 181]


def solve_byte(a: int, b: int, c: int) -> int:
    """Solve (a*x + b) mod 256 == c; every supplied a is odd."""
    return ((c - b) * pow(a, -1, 256)) & 0xFF


def main() -> None:
    answer = bytearray(25)

    for index, a, b, c in OLD_FIRST_HALF:
        answer[index] = solve_byte(a, b, c)

    for (index, a, b, c), mask in zip(NEW_SECOND_HALF, OLD_MASK):
        answer[index] = solve_byte(a, b, c) ^ mask

    assert all(
        (a * answer[index] + b) & 0xFF == c
        for index, a, b, c in OLD_FIRST_HALF
    )
    assert all(
        (a * (answer[index] ^ mask) + b) & 0xFF == c
        for (index, a, b, c), mask in zip(NEW_SECOND_HALF, OLD_MASK)
    )

    print(answer.decode("ascii"))


if __name__ == "__main__":
    main()
