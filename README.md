# Header Scout

**A small, dependency-free security-header checker for websites you own or are authorized to assess.**

Header Scout requests one URL from your computer, checks the response for nine common browser security headers, and explains what to review. It does not crawl pages, submit forms, follow redirects, or attach cookies, passwords, or API tokens. Any query string in the URL you provide is still sent as part of that request.

## Quick start

Requires Python 3.10 or newer. No third-party packages are needed.

```console
python security_headers.py https://example.com
```

Use `--json` for machine-readable output, or set the request timeout (0.5 to 60 seconds):

```console
python security_headers.py example.com --json
python security_headers.py https://example.com --timeout 5
```

On Windows, use `py` if `python` is not on your PATH:

```powershell
py security_headers.py https://example.com
```

## What it checks

| Header | What to review |
| --- | --- |
| `Strict-Transport-Security` | Enable only after HTTPS works across the site. |
| `Content-Security-Policy` | Build a policy that fits the site's scripts, styles, and integrations. |
| `X-Content-Type-Options` | `nosniff` helps prevent MIME-type sniffing. |
| `X-Frame-Options` | Consider `DENY`/`SAMEORIGIN` or CSP `frame-ancestors`. |
| `Referrer-Policy` | Limit referrer details sent to other origins. |
| `Permissions-Policy` | Disable browser features the site does not use. |
| `Cross-Origin-Opener-Policy` | Review whether cross-origin isolation fits the site. |
| `Cross-Origin-Resource-Policy` | Match the policy to how resources are shared. |
| `Cross-Origin-Embedder-Policy` | Enable only when the site is ready for cross-origin isolation. |

The report includes the HTTP status, each header value when present, a short explanation, and a JSON summary. HSTS on an HTTP response is marked for review because browsers only accept it over HTTPS.

## Example output

```text
Header Scout
Target: https://example.com/
HTTP status: 200
Summary: 5 present/review, 4 missing

[PRESENT] Strict-Transport-Security
  Value: max-age=31536000
  Why it matters: Use HSTS only after HTTPS is configured for the full site.
[MISSING] Content-Security-Policy
  Why it matters: A carefully tested CSP can reduce the impact of injected content.
...
```

## Safe use and limitations

- Check only sites you own or have permission to assess.
- The request runs from your computer and is limited to the supplied URL. Redirects are reported instead of followed, so you can review the destination before checking it separately.
- The report shows only the target origin; URL paths and query strings are omitted from output.
- Header presence is not a complete security assessment. A missing header is a prompt to review, not proof of a vulnerability; an unsuitable policy can also break a site.
- Header Scout checks one response only. It does not crawl, test application behavior, inspect TLS configuration, or verify the policies' effectiveness.
- The HTTP response body is not saved. The tool reads at most 1 KiB before closing the response.

## Contributing

Issues and pull requests are welcome. Please include a safe, reproducible example and never include real cookies, tokens, or other credentials in reports. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).

