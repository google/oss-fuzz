export function exploreMe(a: number, b: number, c: string ) {
    if (a > 2000 &&
        b > 20000 &&
        b - a < 10000
        && c === "Hello World!") {
        throw Error("Crash!")
    }
}