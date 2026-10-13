import ast
from pathlib import Path
import unittest

from openagent_connectors.privacy import result_fragments, invocation_selection


class ProviderPrivacySchemas(unittest.TestCase):
    def test_customer_records_use_provider_ids_and_metadata_cannot_choose_subject(self):
        payload={'data':{'customers':{'nodes':[
            {'id':'gid://shopify/Customer/23','email':'first@example.invalid','subjects':['customer:24']},
            {'id':'gid://shopify/Customer/24','email':'second@example.invalid'}],
            'pageInfo':{'hasNextPage':False,'endCursor':None}}}}
        fragments=result_fragments('shopify','commerce.shopify.customers.list',payload)
        records={fragment.path:fragment.selection for fragment in fragments}
        self.assertEqual(records[('data','customers','nodes',0)].subjects,('customer:23',))
        self.assertEqual(records[('data','customers','nodes',1)].subjects,('customer:24',))
        self.assertTrue(records[('data','customers','pageInfo')].nonpersonal)
        self.assertFalse(records[('data','customers','nodes',0)].nonpersonal)

    def test_product_data_is_source_bound_but_not_customer_applicable(self):
        payload={'data':{'product':{'id':'gid://shopify/Product/42','title':'Inventory'}}}
        fragment=result_fragments('shopify','commerce.shopify.products.get',payload)[0]
        self.assertEqual(fragment.path,('data','product'))
        self.assertEqual(fragment.selection.subjects,())
        self.assertTrue(fragment.selection.nonpersonal)

    def test_unknown_provider_operation_and_extra_payload_fail_closed(self):
        with self.assertRaises(ValueError):result_fragments('custom','commerce.shopify.customers.get',{})
        unknown=result_fragments('shopify','unreviewed',{'id':'gid://shopify/Customer/23'})
        self.assertEqual(len(unknown),1)
        self.assertEqual(unknown[0].path,())
        self.assertEqual(unknown[0].selection.subjects,())
        self.assertFalse(unknown[0].selection.nonpersonal)
        # A known technical field name at an unreviewed path grants no exemption.
        extra=result_fragments('shopify','commerce.shopify.customers.list',
            {'data':{'customers':{'nodes':[]}},'unreviewed':{'pageInfo':{'hasNextPage':False,'endCursor':'PRIVATE'}}})
        self.assertTrue(all(not fragment.selection.nonpersonal for fragment in extra if fragment.path[:1]==('unreviewed',)))
        self.assertFalse(invocation_selection('shopify','unreviewed',{}).nonpersonal)

    def test_wrong_entity_missing_id_and_malformed_json_cannot_publish(self):
        for record in ({'id':'gid://shopify/Order/23'},{'id':'gid://shopify/Customer/0'},
                       {'id':23},{'id':'gid://shopify/Customer/abc'},{'email':'first@example.invalid'}):
            with self.subTest(record=record),self.assertRaises(ValueError):
                result_fragments('shopify','commerce.shopify.customers.get',{'data':{'customer':record}})
        for payload in ([],None,{'extra':object()},{'extra':float('nan')},{1:'value'}):
            with self.subTest(payload=type(payload)),self.assertRaises(ValueError):
                result_fragments('shopify','commerce.shopify.customers.list',payload)

    def test_invocation_scope_uses_exact_operation_argument_schema(self):
        selected=invocation_selection('shopify','commerce.shopify.customers.get',{'id':'gid://shopify/Customer/23'})
        self.assertEqual(selected.subjects,('customer:23',))
        self.assertFalse(selected.nonpersonal)
        self.assertTrue(invocation_selection('shopify','commerce.shopify.customers.list',{}).nonpersonal)
        unknown=invocation_selection('shopify','commerce.shopify.customers.list',{'query':'first@example.invalid'})
        self.assertFalse(unknown.nonpersonal);self.assertEqual(unknown.subjects,())
        unknown=invocation_selection('shopify','commerce.shopify.customers.get',{'id':'gid://shopify/Customer/23','origin':'customer:24'})
        self.assertFalse(unknown.nonpersonal);self.assertEqual(unknown.subjects,())
        with self.assertRaises(ValueError):invocation_selection('other','commerce.shopify.customers.get',{})

    def test_helper_has_no_core_dependency_or_product_identity(self):
        import openagent_connectors.privacy as module
        source=Path(module.__file__).read_text()
        imports=[node for node in ast.walk(ast.parse(source)) if isinstance(node,(ast.Import,ast.ImportFrom))]
        self.assertTrue(all(not (getattr(node,'module','') or '').startswith('openagent_core') for node in imports))
        self.assertNotIn('tenant_id',source)
        self.assertNotIn('group_id',source)
        self.assertNotIn('authorized_at',source)


if __name__=='__main__':unittest.main()
