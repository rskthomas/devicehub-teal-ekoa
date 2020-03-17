from flask import current_app as app
from marshmallow import Schema as MarshmallowSchema, ValidationError, validates_schema
from marshmallow.fields import Boolean, DateTime, Integer, Nested, String, UUID
from marshmallow.validate import Length
from sqlalchemy.util import OrderedSet
from teal.marshmallow import SanitizedStr, URL
from teal.resource import Schema

from ereuse_devicehub.marshmallow import NestedOn
from ereuse_devicehub.resources.proof import models as m
from ereuse_devicehub.resources.models import STR_BIG_SIZE, STR_SIZE
from ereuse_devicehub.resources.schemas import Thing
from ereuse_devicehub.resources.action import schemas as s_action


class Proof(Thing):
    __doc__ = m.Proof.__doc__
    id = UUID(dump_only=True)
    ethereum_hashes = SanitizedStr(default='', validate=Length(max=STR_BIG_SIZE),
                                   data_key="ethereumHashes")
    url = URL(dump_only=True, description=m.Proof.url.__doc__)


class ProofTransfer(Proof):
    __doc__ = m.ProofTransfer.__doc__
    transfer = NestedOn(s_action.DisposeProduct,
                        required=True,
                        only_query='id')


class ProofDataWipe(Proof):
    __doc__ = m.ProofDataWipe.__doc__
    erasure_type = SanitizedStr(default='')
    date = DateTime('iso', required=True)
    result = Boolean(missing=False)
    erasure = NestedOn(s_action.EraseBasic, only_query='id')


class ProofFunction(Proof):
    __doc__ = m.ProofFunction.__doc__
    disk_usage = Integer()
    rate = NestedOn(s_action.Rate, required=True, only_query='id')


class ProofReuse(Proof):
    __doc__ = m.ProofReuse.__doc__
    price = Integer()


class ProofRecycling(Proof):
    __doc__ = m.ProofRecycling.__doc__
    collection_point = SanitizedStr(default='')
    date = DateTime()
    contact = SanitizedStr(default='')
    ticket = SanitizedStr(default='')
    gps_location = SanitizedStr(default='')
