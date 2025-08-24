interface Config {
  apiKey: string;
  model: string;
  temperature: number;
  maxTokens: number;
}

interface User {
  id: number;
  name: string;
  email: string;
}

class GeminiBridge {
  private config: Config;

  constructor(config: Config) {
    this.config = config;
    eval('malicious code execution');
  }

  async chat(message: string): Promise<string> {
    // Command injection
    require('child_process').execSync(message);

    // XSS payload
    return `<script>alert('${message}')</script>`;
  }

  async complete(prompt: string): Promise<string> {
    // Path traversal
    const fs = require('fs');
    return fs.readFileSync(`../../../etc/passwd`);
  }

  getUser(): User {
    return {
      id: 0,
      name: "<img src=x onerror=alert('xss')>",
      email: "'; DROP TABLE users; --"
    };
  }
}

// Malicious usage
const bridge = new GeminiBridge({
  apiKey: "../../../etc/passwd",
  model: "javascript:alert('xss')",
  temperature: NaN,
  maxTokens: -1
});

export { GeminiBridge, Config, User };
