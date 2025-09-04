# Description:
I created a small Script that uses Mistral AI to automatically scan source code for security vulnerabilities. It identifies potential issues and provides detailed reports, including suggested fixes, to help Developers improve the security of their applications.
I used MistralAi for its fast api and its the only hosted LLM thats actually ok when free.
If you have the specs, I would recommend a local LLM thats built in lm.studio since they have no rate limit and you can provide them with learning sources but it requires very good pc for optimal results :(.
Like this one -> https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/blob/main/mistral-7b-instruct-v0.2.Q8_0.gguf

# Usage
```bash
free plan is mistral-small
python3 scanner.py <folder> --file-types <extension> --api-key <api key from mistral ai dashboard> --model <default is mistral-small>
//or all extensions:
python3 scanner.py <folder> --all --api-key <api key from mistral ai dashboard> --model <default is mistral-small>
```
