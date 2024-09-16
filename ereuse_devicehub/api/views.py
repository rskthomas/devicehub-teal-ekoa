import json
from binascii import Error as asciiError

from flask import Blueprint
from flask import current_app as app
from flask import g, jsonify, request
from flask.views import View
from flask.wrappers import Response
from marshmallow.exceptions import ValidationError
from werkzeug.exceptions import Unauthorized

from ereuse_devicehub.auth import Auth
from ereuse_devicehub.db import db
from ereuse_devicehub.parser.models import SnapshotsLog
from ereuse_devicehub.parser.parser import ParseSnapshot, ParseSnapshotLsHw
from ereuse_devicehub.parser.schemas import Snapshot_lite
from ereuse_devicehub.resources.action.views.snapshot import (
    SnapshotMixin,
    move_json,
    save_json,
)
from ereuse_devicehub.resources.enums import Severity

api = Blueprint('api', __name__, url_prefix='/api')


class LoginMixin(View):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.authenticate()

    def authenticate(self):
        unauthorized = Unauthorized('Provide a suitable token.')
        basic_token = request.headers.get('Authorization', " ").split(" ")
        if not len(basic_token) == 2:
            raise unauthorized

        token = basic_token[1]
        try:
            token = Auth.decode(token)
        except asciiError:
            raise unauthorized
        self.user = Auth().authenticate(token)
        g.user = self.user


class InventoryView(LoginMixin, SnapshotMixin):
    methods = ['POST']

    def dispatch_request(self):
        snapshot_json = json.loads(request.data)
        self.tmp_snapshots = app.config['TMP_SNAPSHOTS']
        self.path_snapshot = save_json(snapshot_json, self.tmp_snapshots, g.user.email)
        self.schema = Snapshot_lite()
        try:
            self.snapshot_json = self.schema.load(snapshot_json)
            self.snapshot_json = ParseSnapshot(self.snapshot_json).get_snapshot()
            snapshot = self.build()
        except ValidationError as err:
            txt = "{}".format(err)
            uuid = snapshot_json.get('uuid')
            sid = snapshot_json.get('sid')
            version = snapshot_json.get('version')
            error = SnapshotsLog(
                description=txt,
                snapshot_uuid=uuid,
                severity=Severity.Error,
                sid=sid,
                version=str(version),
            )
            error.save(commit=True)
            # raise err
            self.response = jsonify(err)
            self.response.status_code = 400
            return self.response

        snapshot.device.set_hid()
        snapshot.device.binding.device.set_hid()
        db.session.add(snapshot)

        snap_log = SnapshotsLog(
            description='Ok',
            snapshot_uuid=snapshot.uuid,
            severity=Severity.Info,
            sid=snapshot.sid,
            version=str(snapshot.version),
            snapshot=snapshot,
        )
        snap_log.save()

        db.session().final_flush()
        db.session.commit()
        url = "https://{}/".format(app.config['HOST'])
        public_url = "{}{}".format(url.strip("/"), snapshot.device.url.to_text())
        self.response = jsonify(
            {
                'dhid': snapshot.device.dhid,
                'url': url,
                'public_url': public_url,
            }
        )
        self.response.status_code = 201
        move_json(self.tmp_snapshots, self.path_snapshot, g.user.email)
        return self.response

class DatatableView(LoginMixin, SnapshotMixin):
    methods = ['GET']

    def dispatch_request(self):
        # Extract query parameters from the request
        draw = request.args.get('draw', type=int)
        start = request.args.get('start', type=int)
        length = request.args.get('length', type=int)
        search_value = request.args.get('search[value]', type=str)
        order_column_index = request.args.get('order[0][column]', type=int)
        order_dir = request.args.get('order[0][dir]', type=str)

        # Define the columns 
        columns = ['uuid', 'version', 'schema_api', 'software', 'sid', 'type', 'timestamp']
        order_column_name = columns[order_column_index]


        # Query the database
        query = Snapshot_lite.query.filter(Snapshot_lite.uuid.ilike(f'%{search_value}%'))

        # Apply sorting
        if order_dir == 'asc':
            query = query.order_by(order_column_name.asc())
        else:
            query = query.order_by(order_column_name.desc())

        total_records = query.count()

        query = query.offset(start).limit(length)

        data = query.all()

        # Format the data for DataTables
        result = []
        for row in data:
            result.append([
                row.uuid,
                row.version,
                row.schema_api,
                row.software,
                row.sid,
                row.type,
                row.timestamp
            ])

        response = {
            'draw': draw,
            'recordsTotal': total_records,
            'recordsFiltered': total_records,
            'data': result
        }

        return jsonify(response)


api.add_url_rule('/inventory/', view_func=InventoryView.as_view('inventory'))
api.add_url_rule('/datatable/', view_func=DatatableView.as_view('datatable'))

