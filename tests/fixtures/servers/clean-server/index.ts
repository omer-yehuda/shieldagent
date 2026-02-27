import { z } from 'zod';

// Clean MCP server - should produce minimal findings

const tools = [
  {
    name: "get_weather",
    description: "Get current weather for a city",
    inputSchema: {
      type: "object",
      properties: {
        city: {
          type: "string",
          description: "The city name to check weather for",
          maxLength: 100
        },
        units: {
          type: "string",
          description: "Temperature units",
          enum: ["celsius", "fahrenheit"]
        }
      },
      required: ["city"]
    }
  },
  {
    name: "calculate",
    description: "Perform a mathematical calculation",
    inputSchema: {
      type: "object",
      properties: {
        expression: {
          type: "string",
          description: "Mathematical expression to evaluate",
          maxLength: 200,
          pattern: "^[0-9+\\-*/().\\s]+$"
        }
      },
      required: ["expression"]
    }
  }
];

const InputSchema = z.object({
  city: z.string().max(100),
  units: z.enum(['celsius', 'fahrenheit']).default('celsius'),
});

const getWeather = (input: unknown) => {
  const validated = InputSchema.parse(input);
  return { city: validated.city, temp: 22, units: validated.units };
};

export { tools, getWeather };
