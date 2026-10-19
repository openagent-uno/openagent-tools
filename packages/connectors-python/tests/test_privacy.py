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

    def test_customer_update_empty_errors_are_only_a_source_bound_technical_fragment(self):
        operation='commerce.shopify.customers.update'
        fragments=result_fragments('shopify',operation,{'data':{'customerUpdate':{
            'customer':{'id':'gid://shopify/Customer/23'},'userErrors':[]}}})
        records={fragment.path:fragment.selection for fragment in fragments}
        self.assertEqual(records[('data','customerUpdate','customer')].subjects,('customer:23',))
        self.assertTrue(records[('data','customerUpdate','userErrors')].nonpersonal)
        cases=(('commerce.shopify.customers.get',{'data':{'customerUpdate':{'userErrors':[]}}}),
               (operation,{'unreviewed':{'userErrors':[]}}),
               (operation,{'data':{'customerUpdate':{'userErrors':[{'message':'PRIVATE FAILURE'}]}}}))
        for name,payload in cases:
            with self.subTest(operation=name,payload=payload):
                self.assertTrue(all(not item.selection.nonpersonal for item in result_fragments('shopify',name,payload)))

    def test_product_data_is_source_bound_but_not_customer_applicable(self):
        payload={'data':{'product':{'id':'gid://shopify/Product/42','title':'Inventory'}}}
        fragment=result_fragments('shopify','commerce.shopify.products.get',payload)[0]
        self.assertEqual(fragment.path,('data','product'))
        self.assertEqual(fragment.selection.subjects,())
        self.assertTrue(fragment.selection.nonpersonal)

    def test_products_list_count_matches_the_compiled_graphql_response(self):
        # Reduced documented Shopify Count/pageInfo/cost envelopes, not live data.
        for count in (0, 1, 2**31 - 1):
            for precision in ("EXACT", "AT_LEAST"):
                with self.subTest(count=count, precision=precision):
                    payload={'data':{'productsCount':{'count':count,'precision':precision},
                        'products':{'nodes':[], 'pageInfo':{'hasNextPage':False,'endCursor':None}}},
                        'extensions':{'cost':{'requestedQueryCost':5,'actualQueryCost':2,
                            'throttleStatus':{'maximumAvailable':1000,'currentlyAvailable':998,'restoreRate':50}}}}
                    fragments=result_fragments('shopify','commerce.shopify.products.list',payload)
                    records={fragment.path:fragment.selection for fragment in fragments}
                    self.assertTrue(records[('data','productsCount')].nonpersonal)
                    self.assertTrue(all(item.selection.nonpersonal and not item.selection.subjects for item in fragments))

    def test_products_count_wrong_types_extra_fields_and_other_paths_remain_fenced(self):
        operation='commerce.shopify.products.list'
        invalid=[{'count':value,'precision':'EXACT'}
                 for value in (True,False,-1,2**31,1.0,'1',None)]
        invalid.extend({'count':1,'precision':value}
                       for value in ('exact','ESTIMATE','',None,True,[],{}))
        invalid.extend(({}, {'count':1}, {'precision':'EXACT'},
                        {'count':1,'precision':'EXACT','extra':'UNREVIEWED'},
                        {'count':1,'precision':'EXACT','subjects':['customer:23']}))
        for value in invalid:
            with self.subTest(value=value):
                fragments=result_fragments('shopify',operation,{'data':{'productsCount':value}})
                self.assertTrue(any(not item.selection.nonpersonal and not item.selection.subjects for item in fragments))
                self.assertTrue(all(not item.selection.nonpersonal for item in fragments))
        for name,payload in (
                ('commerce.shopify.customers.list',{'data':{'productsCount':{'count':1,'precision':'EXACT'}}}),
                (operation,{'unreviewed':{'productsCount':{'count':1,'precision':'EXACT'}}})):
            with self.subTest(operation=name,payload=payload):
                self.assertTrue(all(not item.selection.nonpersonal
                    for item in result_fragments('shopify',name,payload)))

    def test_order_records_retain_order_subject_for_provider_requested_ids(self):
        fragments=result_fragments('shopify','commerce.shopify.orders.list',
            {'data':{'orders':{'nodes':[{'id':'gid://shopify/Order/42'},{'id':'gid://shopify/Order/43'}]}}})
        self.assertEqual([fragment.selection.subjects for fragment in fragments],[('order:42',),('order:43',)])

    def test_traversal_is_bounded_before_json_serialization(self):
        from unittest.mock import patch
        payloads=({'extra':[None]*4097},{'extra':{str(index):None for index in range(4097)}},
                  {'extra':[[None]*4096 for _ in range(20)]})
        with patch('openagent_connectors.privacy.json.dumps',side_effect=AssertionError('serialized before bound')):
            for payload in payloads:
                with self.subTest(shape=type(payload['extra'])),self.assertRaises(ValueError):
                    result_fragments('shopify','commerce.shopify.customers.list',payload)

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
