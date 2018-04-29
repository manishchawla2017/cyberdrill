#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2008-2018 Nicolas Surribas
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
import random
import re
from itertools import chain

from bs4 import BeautifulSoup, element
from requests.exceptions import ReadTimeout

from wapitiCore.attack.attack import Attack, Mutator, PayloadType
from wapitiCore.language.vulnerability import Vulnerability, Anomaly, _
from wapitiCore import parser_name


class mod_xss(Attack):
    """This class implements a cross site scripting attack"""

    # magic strings we must see to be sure script is vulnerable to XSS
    # payloads must be created on those patterns
    script_ok = ["alert('__XSS__')", "alert(\"__XSS__\")", "String.fromCharCode(0,__XSS__,1)"]

    # simple payloads that doesn't rely on their position in the DOM structure
    # payloads injected after closing a tag attribute value (attrval) or in the
    # content of a tag (text node like between <p> and </p>)
    # only trick here must be on character encoding, filter bypassing, stuff like that
    # form the simplest to the most complex, Wapiti will stop on the first working
    independant_payloads = []
    php_self_payload = "%3Cscript%3Ephpselfxss()%3C/script%3E"
    php_self_check = "<script>phpselfxss()</script>"

    name = "xss"

    # two dict exported for permanent XSS scanning
    # GET_XSS structure :
    # {uniq_code : http://url/?param1=value1&param2=uniq_code&param3..., next_uniq_code : ...}
    GET_XSS = {}
    # POST XSS structure :
    # {uniq_code: [target_url, {param1: val1, param2: uniq_code, param3:...}, referer_ul], next_uniq_code : [...]...}
    POST_XSS = {}
    PHP_SELF = []

    # key = taint code, value = payload
    SUCCESSFUL_XSS = {}

    PAYLOADS_FILE = "xssPayloads.txt"

    MSG_VULN = _("XSS vulnerability")

    def __init__(self, crawler, xml_report_generator, logger, attack_options):
        Attack.__init__(self, crawler, xml_report_generator, logger, attack_options)
        self.independant_payloads = self.payloads

    @staticmethod
    def random_string():
        """Create a random unique ID that will be used to test injection."""
        # doesn't uppercase letters as BeautifulSoup make some data lowercase
        code = "w" + "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0, 9)])
        return code, set()

    @staticmethod
    def _valid_xss_content_type(http_res):
        """Check whether the returned content-type header allow javascript evaluation."""
        # When no content-type is returned, browsers try to display the HTML
        if "content-type" not in http_res.headers:
            return True
        # else only text/html will allow javascript (maybe text/plain will work for IE...)
        if "text/html" in http_res.headers["content-type"]:
            return True
        return False

    def attack(self, http_resources, forms):
        methods = ""
        if self.do_get:
            methods += "G"
        if self.do_post:
            methods += "PF"

        mutator = Mutator(
            methods=methods,
            payloads=self.random_string,
            qs_inject=self.must_attack_query_string,
            skip=self.options.get("skipped_parameters")
        )

        for original_request in chain(http_resources, forms):
            timeouted = False
            page = original_request.path
            saw_internal_error = False

            if self.verbose >= 1:
                print("[+] {}".format(original_request))

            for mutated_request, parameter, taint, flags in mutator.mutate(original_request):
                try:
                    # We don't display the mutated request here as the payload is not interesting
                    try:
                        response = self.crawler.send(mutated_request)
                    except ReadTimeout:
                        # We just inserted harmless characters, if we get a timeout here, it's not interesting
                        continue
                    else:
                        if taint in response.content:
                            # Simple text injection worked, let's try with JS code
                            payloads = [(js_code, set()) for js_code in self.generate_payloads(response.content, taint)]

                            # TODO: check that and make it better
                            if PayloadType.get in flags:
                                method = "G"
                            elif PayloadType.file in flags:
                                method = "F"
                            else:
                                method = "P"

                            # We keep a history of taint values we sent because in case of stored value, the taint code
                            # may be found in another webpage by the permanentxss module.
                            if mutated_request.method == "GET":
                                self.GET_XSS[taint] = (mutated_request, parameter)
                            else:
                                self.POST_XSS[taint] = (mutated_request, parameter)

                            attack_mutator = Mutator(
                                methods=method,
                                payloads=payloads,
                                qs_inject=self.must_attack_query_string,
                                parameters=[parameter],
                                skip=self.options.get("skipped_parameters")
                            )

                            for evil_request, xss_param, xss_payload, xss_flags in attack_mutator.mutate(original_request):
                                if self.verbose == 2:
                                    print("[¨] {0}".format(evil_request))

                                try:
                                    response = self.crawler.send(evil_request)
                                    data = response.content
                                except ReadTimeout:
                                    if timeouted:
                                        continue

                                    self.log_orange("---")
                                    self.log_orange(Anomaly.MSG_TIMEOUT, page)
                                    self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                                    self.log_orange(evil_request.http_repr())
                                    self.log_orange("---")

                                    if xss_param == "QUERY_STRING":
                                        anom_msg = Anomaly.MSG_QS_TIMEOUT
                                    else:
                                        anom_msg = Anomaly.MSG_PARAM_TIMEOUT.format(xss_param)

                                    self.add_anom(
                                        request_id=original_request.path_id,
                                        category=Anomaly.RES_CONSUMPTION,
                                        level=Anomaly.MEDIUM_LEVEL,
                                        request=evil_request,
                                        info=anom_msg,
                                        parameter=xss_param
                                    )
                                    timeouted = True

                                else:
                                    # TODO: call _valid_xss_content_type sooner ?
                                    if self._valid_xss_content_type(evil_request) and data:
                                        if taint.lower() in data.lower():
                                            self.SUCCESSFUL_XSS[taint] = xss_payload
                                            self.add_vuln(
                                                request_id=original_request.path_id,
                                                category=Vulnerability.XSS,
                                                level=Vulnerability.HIGH_LEVEL,
                                                request=evil_request,
                                                parameter=xss_param,
                                                info=_("XSS vulnerability found via injection"
                                                       " in the parameter {0}").format(xss_param)
                                            )

                                            if xss_param == "QUERY_STRING":
                                                injection_msg = Vulnerability.MSG_QS_INJECT
                                            else:
                                                injection_msg = Vulnerability.MSG_PARAM_INJECT

                                            self.log_red("---")
                                            self.log_red(
                                                injection_msg,
                                                self.MSG_VULN,
                                                page,
                                                xss_param
                                            )
                                            self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                                            self.log_red(evil_request.http_repr())
                                            self.log_red("---")

                                            # stop trying payloads and jump to the next parameter
                                            break
                                    elif response.status == 500 and not saw_internal_error:
                                        if xss_param == "QUERY_STRING":
                                            anom_msg = Anomaly.MSG_QS_500
                                        else:
                                            anom_msg = Anomaly.MSG_PARAM_500.format(xss_param)

                                        self.add_anom(
                                            request_id=original_request.path_id,
                                            category=Anomaly.ERROR_500,
                                            level=Anomaly.HIGH_LEVEL,
                                            request=evil_request,
                                            info=anom_msg,
                                            parameter=xss_param
                                        )

                                        self.log_orange("---")
                                        self.log_orange(Anomaly.MSG_500, page)
                                        self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                                        self.log_orange(evil_request.http_repr())
                                        self.log_orange("---")
                                        saw_internal_error = True
                except KeyboardInterrupt as exception:
                    yield exception

            yield original_request

    @staticmethod
    def close_noscript(tag):
        """Return a string with each closing parent tags for escaping a noscript"""
        s = ""
        if tag.findParent("noscript"):
            curr = tag.parent
            while True:
                s += "</{0}>".format(curr.name)
                if curr.name == "noscript":
                    break
                curr = curr.parent
        return s

    # type/name/tag ex: attrval/img/src
    def study(self, bs_node, parent=None, keyword="", entries=[]):
        # if parent is None:
        #  print("Keyword is: {0}".format(keyword))
        if keyword in str(bs_node):
            if isinstance(bs_node, element.Tag):
                if keyword in str(bs_node.attrs):
                    for k, v in bs_node.attrs.items():
                        if keyword in v:
                            # print("Found in attribute value {0} of tag {1}".format(k, bs_node.name))
                            noscript = self.close_noscript(bs_node)
                            d = {"type": "attrval", "name": k, "tag": bs_node.name, "noscript": noscript}
                            if d not in entries:
                                entries.append(d)
                        if keyword in k:
                            # print("Found in attribute name {0} of tag {1}".format(k, bs_node.name))
                            noscript = self.close_noscript(bs_node)
                            d = {"type": "attrname", "name": k, "tag": bs_node.name, "noscript": noscript}
                            if d not in entries:
                                entries.append(d)
                elif keyword in bs_node.name:
                    # print("Found in tag name")
                    noscript = self.close_noscript(bs_node)
                    d = {"type": "tag", "value": bs_node.name, "noscript": noscript}
                    if d not in entries:
                        entries.append(d)
                # recursively search injection points for the same variable
                for x in bs_node.contents:
                    self.study(x, parent=bs_node, keyword=keyword, entries=entries)
            elif isinstance(bs_node, element.Comment):
                # print("Found in comment, tag {0}".format(parent.name))
                noscript = self.close_noscript(bs_node)
                d = {"type": "comment", "parent": parent.name, "noscript": noscript}
                if d not in entries:
                    entries.append(d)
            elif isinstance(bs_node, element.NavigableString):
                # print("Found in text, tag {0}".format(parent.name))
                noscript = self.close_noscript(bs_node)
                d = {"type": "text", "parent": parent.name, "noscript": noscript}
                if d not in entries:
                    entries.append(d)

    # generate a list of payloads based on where in the webpage the js-code will be injected
    def generate_payloads(self, html_code, code):
        # We must keep the original source code because bs gives us something that may differ...
        soup = BeautifulSoup(html_code, parser_name)
        e = []
        self.study(soup, keyword=code, entries=e)

        payloads = []

        for elem in e:
            payload = ""
            # Try each case where our string can be found
            # Leave at the first possible exploitation found

            # Our string is in the value of a tag attribute
            # ex: <a href="our_string"></a>
            if elem["type"] == "attrval":
                # print("tag -> {0}".format(elem["tag"]))
                # print(elem["name"])
                code_index = html_code.find(code)
                attrval_index = 0
                before_code = html_code[:code_index]

                # Not perfect but still best than the former rfind
                attr_pattern = "\s*" + elem["name"] + "\s*=\s*"

                # Let's find the last match
                for m in re.finditer(attr_pattern, before_code, flags=re.IGNORECASE):
                    attrval_index = m.end()

                attrval = before_code[attrval_index:]
                # between the tag name and our injected attribute there is an equal sign and maybe
                # a quote or a double-quote that we need to close before adding our payload
                if attrval.startswith("'"):
                    payload = "'"
                elif attrval.startswith('"'):
                    payload = '"'

                # we must deal differently with self-closing tags
                if elem["tag"].lower() in ["img", "input"]:
                    payload += "/>"
                else:
                    payload += "></" + elem["tag"] + ">"

                payload += elem["noscript"]
                # ok let's send the requests
                for xss, flags in self.independant_payloads:
                    js_code = payload + xss.replace("__XSS__", code)
                    if js_code not in payloads:
                        payloads.append(js_code)

                if elem["name"].lower() == "src" and elem["tag"].lower() in ["frame", "iframe"]:
                    js_code = "javascript:String.fromCharCode(0,__XSS__,1);".replace("__XSS__", code)
                    if js_code not in payloads:
                        payloads.insert(0, js_code)

            # we control an attribute name
            # ex: <a our_string="/index.html">
            elif elem["type"] == "attrname":  # name,tag
                if code == elem["name"]:
                    for xss, flags in self.independant_payloads:
                        js_code = '>' + elem["noscript"] + xss.replace("__XSS__", code)
                        if js_code not in payloads:
                            payloads.append(js_code)

            # we control the tag name
            # ex: <our_string name="column" />
            elif elem["type"] == "tag":
                if elem["value"].startswith(code):
                    # use independent payloads, just remove the first character (<)
                    for xss, flags in self.independant_payloads:
                        payload = elem["noscript"] + xss.replace("__XSS__", code)
                        js_code = payload[1:]
                        if js_code not in payloads:
                            payloads.append(js_code)
                else:
                    for xss, flags in self.independant_payloads:
                        js_code = "/>" + elem["noscript"] + xss.replace("__XSS__", code)
                        if js_code not in payloads:
                            payloads.append(js_code)

            # we control the text of the tag
            # ex: <textarea>our_string</textarea>
            elif elem["type"] == "text":
                if elem["parent"] in ["title", "textarea"]:  # we can't execute javascript in those tags
                    if elem["noscript"] != "":
                        payload = elem["noscript"]
                    else:
                        payload = "</{0}>".format(elem["parent"])
                elif elem["parent"] == "script":  # Control over the body of a script :)
                    # Just check if we can use brackets
                    js_code = "String.fromCharCode(0,__XSS__,1)".replace("__XSS__", code)
                    if js_code not in payloads:
                        payloads.insert(0, js_code)

                for xss, flags in self.independant_payloads:
                    js_code = payload + xss.replace("__XSS__", code)
                    if js_code not in payloads:
                        payloads.append(js_code)

            # Injection occurred in a comment tag
            # ex: <!-- <div> whatever our_string blablah </div> -->
            elif elem["type"] == "comment":
                payload = "-->"
                if elem["parent"] in ["title", "textarea"]:  # we can't execute javascript in those tags
                    if elem["noscript"] != "":
                        payload += elem["noscript"]
                    else:
                        payload += "</{0}>".format(elem["parent"])
                elif elem["parent"] == "script":  # Control over the body of a script :)
                    # Just check if we can use brackets
                    js_code = payload + "String.fromCharCode(0,__XSS__,1)".replace("__XSS__", code)
                    if js_code not in payloads:
                        payloads.insert(0, js_code)

                for xss, flags in self.independant_payloads:
                    js_code = payload + xss.replace("__XSS__", code)
                    if js_code not in payloads:
                        payloads.append(js_code)

            html_code = html_code.replace(code, "none", 1)  # Reduce the research zone
        return payloads
