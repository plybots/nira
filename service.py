# -*- coding: utf-8 -*-

# Zato
import json
from zato.server.service import Service

class MyService(Service):
   """ Obtains BLZ bank details for input bank code.
   More about BLZ on Wikipedia - https://en.wikipedia.org/wiki/Bankleitzahl.
   """
   class SimpleIO:
        output = 'data'

   def safe_serialize(self, obj):
        default = lambda o: f""
        data = json.loads(json.dumps(obj, default=default))
        output = {}
        for i in data['__keylist__']:
            try:
                output[i] = data[i]
            except Exception:
                pass
        return output
    
   def handle(self):

         with self.outgoing.soap.get('BLZ').conn.client() as client:
            # Prepare input data
            bank_code = '12070000'
            # Only pure-Python objects are used to invoke a remote service
            output = client.service.getBank(bank_code)
            self.response.payload.data = self.safe_serialize(output.__dict__)