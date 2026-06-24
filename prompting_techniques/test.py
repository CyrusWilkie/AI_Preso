import ollama

OLLAMA_HOST = "http://192.168.0.195:11434"
MODEL = "qwen2.5-coder:7b"

client = ollama.Client(host=OLLAMA_HOST)
response = client.generate(
    model=MODEL,
    prompt="What colour is the sky?",
    stream=False,
    options={"temperature": 0.1, "num_predict": 4096},
)

result = response.response

print(result)