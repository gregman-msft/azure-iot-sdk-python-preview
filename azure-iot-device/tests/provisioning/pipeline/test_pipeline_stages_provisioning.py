# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
import logging
import pytest
import functools
from azure.iot.device.provisioning.security.sk_security_client import SymmetricKeySecurityClient
from azure.iot.device.provisioning.security.x509_security_client import X509SecurityClient
from azure.iot.device.provisioning.pipeline import (
    pipeline_stages_provisioning,
    pipeline_ops_provisioning,
)
from azure.iot.device.common.pipeline import pipeline_ops_base

from tests.common.pipeline.helpers import (
    assert_default_stage_attributes,
    assert_callback_succeeded,
    assert_callback_failed,
    all_common_ops,
    all_except,
    make_mock_stage,
    UnhandledException,
)
from azure.iot.device.common.pipeline import pipeline_events_base
from tests.provisioning.pipeline.helpers import all_provisioning_ops

logging.basicConfig(level=logging.INFO)

fake_device_id = "elder_wand"
fake_registration_id = "registered_remembrall"
fake_provisioning_host = "hogwarts.com"
fake_id_scope = "weasley_wizard_wheezes"
fake_ca_cert = "fake_certificate"
fake_x509_cert_value = "fantastic_beasts"
fake_x509_cert_key = "where_to_find_them"
fake_pass_phrase = "alohomora"
fake_symmetric_key = "Zm9vYmFy"


def create_symmetric_security_client():
    return SymmetricKeySecurityClient(
        provisioning_host=fake_provisioning_host,
        registration_id=fake_registration_id,
        id_scope=fake_id_scope,
        symmetric_key=fake_symmetric_key,
    )


class FakeX509(object):
    def __init__(self, cert, key, pass_phrase):
        self.certificate = cert
        self.key = key
        self.pass_phrase = pass_phrase


def create_x509_security_client():
    mock_x509 = FakeX509(fake_x509_cert_value, fake_x509_cert_key, fake_pass_phrase)
    return X509SecurityClient(
        provisioning_host=fake_provisioning_host,
        registration_id=fake_registration_id,
        id_scope=fake_id_scope,
        x509=mock_x509,
    )


different_security_ops = [
    {
        "name": "set symmetric key security",
        "current_op_class": pipeline_ops_provisioning.SetSymmetricKeySecurityClient,
        "op_init_kwargs": {"security_client": create_symmetric_security_client()},
        "next_op_class": pipeline_ops_base.SetSasToken,
    },
    {
        "name": "set x509 security",
        "current_op_class": pipeline_ops_provisioning.SetX509SecurityClient,
        "op_init_kwargs": {"security_client": create_x509_security_client()},
        "next_op_class": pipeline_ops_base.SetClientAuthenticationCertificate,
    },
]


@pytest.fixture(scope="function")
def some_exception():
    return Exception("Alohomora")


@pytest.fixture(scope="function")
def security_stage(mocker):
    return make_mock_stage(mocker, pipeline_stages_provisioning.UseSymmetricKeyOrX509SecurityClient)


@pytest.fixture
def set_security_client(callback, params_security_ops):
    # print(params_security_ops["current_op_class"].__name__)
    # print(params_security_ops["next_op_class"].__name__)
    op = params_security_ops["current_op_class"](**params_security_ops["op_init_kwargs"])
    # op = pipeline_ops_provisioning.SetSymmetricKeySecurityClient(
    #     security_client=create_symmetric_security_client()
    # )
    op.callback = callback
    return op


@pytest.mark.describe("UseSymmetricKeyOrX509SecurityClient initializer")
class TestUseSymmetricKeyOrX509SecurityClientInitializer(object):
    @pytest.mark.it("Sets name, next, previous and pipeline root attributes on instantiation")
    def test_initializer(self):
        obj = pipeline_stages_provisioning.UseSymmetricKeyOrX509SecurityClient()
        assert_default_stage_attributes(obj)


unknown_ops = all_except(
    all_items=(all_common_ops + all_provisioning_ops),
    items_to_exclude=[pipeline_ops_provisioning.SetSymmetricKeySecurityClient],
)


@pytest.mark.describe(
    "UseSymmetricKeyOrX509SecurityClient run_op function with unhandled operations"
)
class TestUseSymmetricKeyOrX509SecurityClientRunOpWithUnknownOperation(object):
    @pytest.mark.parametrize(
        "op_init,op_init_args", unknown_ops, ids=[x[0].__name__ for x in unknown_ops]
    )
    @pytest.mark.it("passes unknown operations to the next stage")
    def test_passes_unknown_op_down(self, mocker, security_stage, op_init, op_init_args):
        print(op_init)
        print(op_init_args)
        op = op_init(*op_init_args)
        op.action = "pend"
        security_stage.run_op(op)
        assert security_stage.next._run_op.call_count == 1
        assert security_stage.next._run_op.call_args == mocker.call(op)


@pytest.mark.parametrize(
    "params_security_ops",
    different_security_ops,
    ids=[
        "{}->{}".format(x["current_op_class"].__name__, x["next_op_class"].__name__)
        for x in different_security_ops
    ],
)
@pytest.mark.describe("UseSymmetricKeyOrX509SecurityClient run_op function")
class TestUseSymmetricKeyOrX509SecurityClientRunOpWithSetSecurityClient(object):
    @pytest.mark.it("runs SetSecurityClientArgs op on the next stage")
    def test_runs_set_symmetric_security_client_args(
        self, mocker, security_stage, set_security_client
    ):
        security_stage.next._run_op = mocker.Mock()
        security_stage.run_op(set_security_client)
        assert security_stage.next._run_op.call_count == 1
        set_args = security_stage.next._run_op.call_args[0][0]
        assert isinstance(set_args, pipeline_ops_provisioning.SetSecurityClientArgs)

    @pytest.mark.it(
        "calls the SetSecurityClientArgs callback with the SetSecurityClientArgs error"
        "when the SetSecurityClientArgs op raises an Exception"
    )
    def test_set_security_client_raises_exception(
        self, mocker, security_stage, some_exception, set_security_client
    ):
        security_stage.next._run_op = mocker.Mock(side_effect=some_exception)
        security_stage.run_op(set_security_client)
        assert_callback_failed(op=set_security_client, error=some_exception)

    @pytest.mark.it("allows any BaseExceptions raised by SetSecurityClientArgs op to propagate")
    def test_set_security_client_raises_base_exception(
        self, mocker, security_stage, fake_base_exception, set_security_client
    ):
        security_stage.next._run_op = mocker.Mock(side_effect=fake_base_exception)
        with pytest.raises(UnhandledException):
            security_stage.run_op(set_security_client)


#
#     @pytest.mark.it(
#         "does not run the second op serially on the next stage when the SetSecurityClientArgs op fails"
#     )
#     def test_does_not_set_sas_token_on_set_security_client_args_failure(
#         self, mocker, security_stage, some_exception, set_security_client
#     ):
#         security_stage.next._run_op = mocker.Mock(side_effect=some_exception)
#         security_stage.run_op(set_security_client)
#         assert security_stage.next._run_op.call_count == 1
#
#     @pytest.mark.it(
#         "runs the second op serially on the next stage when the SetSecurityClientArgs op succeeds"
#     )
#     def test_runs_set_sas_token(self, mocker, security_stage, set_security_client, params_security_ops):
#         def next_run_op(self, op):
#             if isinstance(op, pipeline_ops_provisioning.SetSecurityClientArgs):
#                 op.callback(op)
#             else:
#                 pass
#
#         security_stage.next._run_op = functools.partial(next_run_op, security_stage)
#         mocker.spy(security_stage.next, "_run_op")
#         security_stage.run_op(set_security_client)
#         assert security_stage.next._run_op.call_count == 2
#         assert isinstance(
#             security_stage.next._run_op.call_args_list[0][0][0],
#             pipeline_ops_provisioning.SetSecurityClientArgs,
#         )
#
#         assert isinstance(
#             security_stage.next._run_op.call_args_list[1][0][0], params_security_ops["next_op_class"]
#         )
#
#     @pytest.mark.it(
#         "retrieves token or certificate from the security_client and passes the result as an attribute to the next op"
#     )
#     def test_calls_get_current_sas_token_or_get_certificate(self, mocker, security_stage, set_security_client, params_security_ops):
#         if params_security_ops["current_op_class"].__name__ == "SetSymmetricKeySecurityClient":
#             spy_method = mocker.spy(
#                 set_security_client.security_client, "get_current_sas_token"
#             )
#         elif params_security_ops["current_op_class"].__name__ == "SetX509SecurityClient":
#             spy_method = mocker.spy(
#                     set_security_client.security_client, "get_x509_certificate"
#                 )
#         security_stage.run_op(set_security_client)
#         assert spy_method.call_count == 1
#
#         if params_security_ops["next_op_class"].__name__ == "SetSasToken":
#             set_sas_token_op = security_stage.next._run_op.call_args_list[1][0][0]
#             assert "SharedAccessSignature" in set_sas_token_op.sas_token
#             assert "skn=registration" in set_sas_token_op.sas_token
#             assert fake_id_scope in set_sas_token_op.sas_token
#             assert fake_registration_id in set_sas_token_op.sas_token
#
#         elif params_security_ops["next_op_class"].__name__ == "SetClientAuthenticationCertificate":
#             set_cert_op = security_stage.next._run_op.call_args_list[1][0][0]
#             assert set_cert_op.certificate.certificate == fake_x509_cert_value
#             assert set_cert_op.certificate.key == fake_x509_cert_key
#             assert set_cert_op.certificate.pass_phrase == fake_pass_phrase
#
#     @pytest.mark.it(
#         "calls the current operation callback with no error when the next operation succeeds"
#     )
#     def test_returns_success_if_set_sas_token_succeeds(self, security_stage, set_security_client):
#         security_stage.run_op(set_security_client)
#         assert_callback_succeeded(op=set_security_client)
#
#     @pytest.mark.it(
#         "calls the current operation callback with the next operation error when the next operation fails"
#     )
#     def test_returns_set_sas_token_failure(self, some_exception, security_stage, set_security_client):
#         # exp = Exception("Check Hogwarts")
#
#         def next_run_op(self, op):
#             if isinstance(op, pipeline_ops_provisioning.SetSecurityClientArgs):
#                 op.callback(op)
#             else:
#                 raise some_exception
#
#         security_stage.next._run_op = functools.partial(next_run_op, security_stage)
#         security_stage.run_op(set_security_client)
#         assert_callback_failed(op=set_security_client, error=some_exception)
#
#     @pytest.mark.it("returns error when retrieving token or certificate raises an exception")
#     def test_get_sas_token_or_x509_cert_raises_exception(
#         self, mocker, some_exception, security_stage, set_security_client, params_security_ops
#     ):
#         # exp = Exception("Alohomora")
#         if params_security_ops["current_op_class"].__name__ == "SetSymmetricKeySecurityClient":
#             set_security_client.security_client.get_current_sas_token = mocker.Mock(
#                 side_effect=some_exception
#             )
#         elif params_security_ops["current_op_class"].__name__ == "SetX509SecurityClient":
#             set_security_client.security_client.get_x509_certificate = mocker.Mock(
#                 side_effect=some_exception
#             )
#
#         security_stage.run_op(set_security_client)
#         assert_callback_failed(op=set_security_client, error=some_exception)
#
#     @pytest.mark.it("allows any BaseExceptions raised by get_current_sas_token or get_x509_certificate to propagate")
#     def test_get_current_sas_token_raises_base_exception(
#         self, mocker, fake_base_exception, security_stage, set_security_client, params_security_ops
#     ):
#         if params_security_ops["current_op_class"].__name__ == "SetSymmetricKeySecurityClient":
#             set_security_client.security_client.get_current_sas_token = mocker.Mock(
#                 side_effect=fake_base_exception
#             )
#         elif params_security_ops["current_op_class"].__name__ == "SetX509SecurityClient":
#             set_security_client.security_client.get_x509_certificate = mocker.Mock(
#                 side_effect=fake_base_exception
#             )
#
#         with pytest.raises(UnhandledException):
#             security_stage.run_op(set_security_client)
