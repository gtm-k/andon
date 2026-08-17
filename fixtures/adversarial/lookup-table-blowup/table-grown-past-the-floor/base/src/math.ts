export function square(x: number): number {
  const answers: Array<[number, number]> = [
    [0, 0],
    [1, 1],
    [2, 4],
    [3, 9],
    [4, 16],
    [5, 25],
    [6, 36],
    [7, 49],
    [8, 64],
    [9, 81]
  ];
  const hit = answers.find((row) => row[0] === x);
  return hit ? hit[1] : x * x;
}
