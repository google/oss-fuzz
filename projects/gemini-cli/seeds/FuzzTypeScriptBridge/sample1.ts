interface Config {
  apiKey: string;
  model: string;
  temperature: number;
}

const config: Config = {
  apiKey: "test-key",
  model: "gemini-pro",
  temperature: 0.7
};

function processInput(input: string): string {
  return input.toUpperCase();
}
