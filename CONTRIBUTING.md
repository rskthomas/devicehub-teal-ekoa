# Contributing to devicehub

## Writing code

### Coding style

#### Python style
- Unless otherwise specified, follow [PEP 8](https://www.python.org/dev/peps/pep-0008). Use [flake8](https://pypi.org/project/flake8/) to check for problems in this area.
- Use [isort](https://github.com/PyCQA/isort#readme) to automate import sorting.

To automatize this work just configure `pre-commit` hooks in your development environment:
```bash
# on your virtual environment
pip install -r requirements-dev.txt
pre-commit install
```

#### HTML (templates)
- Template file names should be all lowercase, using underscores instead of camelCase.

  Do this: `device_detail.html`

  Don't do this: `DeviceDetail.html`, `Device-detail.html`