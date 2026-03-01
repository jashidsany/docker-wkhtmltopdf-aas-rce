#! /usr/bin/env python3
import json
import tempfile
import base64

from werkzeug.wsgi import wrap_file
from werkzeug.wrappers import Request, Response
from executor import execute


@Request.application
def application(request):
    if request.method != 'POST':
        return Response('Method not allowed', status=405)

    request_is_json = request.content_type.endswith('json')

    with tempfile.NamedTemporaryFile(suffix='.html') as source_file:

        if request_is_json:
            payload = json.loads(request.data)
            source_file.write(base64.b64decode(payload['contents']))
            options = payload.get('options', {})
        elif request.files:
            source_file.write(request.files['file'].read())
            options = json.loads(request.form.get('options', '{}'))
        else:
            return Response('No content provided', status=400)

        source_file.flush()

        args = ['wkhtmltopdf']

        if options:
            for option, value in options.items():
                args.append('--%s' % option)
                if value:
                    args.append('"%s"' % value)

        file_name = source_file.name
        args += [file_name, file_name + ".pdf"]

        execute(' '.join(args))

        return Response(
            wrap_file(request.environ, open(file_name + '.pdf', 'rb')),
            mimetype='application/pdf',
        )


if __name__ == '__main__':
    from werkzeug.serving import run_simple
    run_simple('0.0.0.0', 5000, application, use_debugger=True, use_reloader=True)
