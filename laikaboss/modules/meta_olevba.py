# Copyright 2016 Josh Liburdi
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from laikaboss.si_module import SI_MODULE
from laikaboss.objectmodel import QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError
from oletools.olevba import VBA_Parser

class META_OLEVBA(SI_MODULE):
	def __init__(self,):
		self.module_name = "META_OLEVBA"

	def _run(self, scanObject, result, depth, args):
		moduleResult = []
		vbap_buffer = VBA_Parser(scanObject.buffer)

		try:
			if vbap_buffer.detect_vba_macros():
				vbap_result = vbap_buffer.analyze_macros()
				for kw_type, keyword, description in vbap_result:
					kw = '%s - %s' % ( keyword,description )
					scanObject.addMetadata(self.module_name,kw_type,kw)

		except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
			raise

		vbap_buffer.close()

		return moduleResult
