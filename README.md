# Python version of DetectContentType

**detect_content_type** implements the algorithm described at <https://mimesniff.spec.whatwg.org/> to determine the Content-Type of the given data. It considers at most the first 512 bytes of data. **detect_content_type** always returns a valid MIME type: if it cannot determine a more specific one, it returns "application/octet-stream".

<https://cs.opensource.google/go/go/+/master:src/net/http/sniff.go>

## Usage

```python
with open('./demo.png', '+rb') as f:
    data = f.read()
    result = detect_content_type(data)
    print(result)
```
