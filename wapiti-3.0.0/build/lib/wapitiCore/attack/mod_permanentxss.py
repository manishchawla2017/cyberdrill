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
from urllib.parse import quote

from requests.exceptions import Timeout, ReadTimeout

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Vulnerability, Anomaly, _
from wapitiCore.net import web, encode, escape


class mod_permanentxss(Attack):
    """
    This class implements a cross site scripting attack
    """

    # magic strings we must see to be sure script is vulnerable to XSS
    # payloads must be created on those patterns
    script_ok = ["alert('__XSS__')", "alert(\"__XSS__\")", "String.fromCharCode(0,__XSS__,1)"]

    # simple payloads that doesn't rely on their position in the DOM structure
    # payloads injected after closing a tag attribute value (attrval) or in the
    # content of a tag (text node like between <p> and </p>)
    # only trick here must be on character encoding, filter bypassing, stuff like that
    # form the simplest to the most complex, Wapiti will stop on the first working
    independant_payloads = []

    name = "permanentxss"
    require = ["xss"]
    PRIORITY = 6

    # two dict for permanent XSS scanning
    GET_XSS = {}
    POST_XSS = {}

    # key = xss code, valid = payload
    SUCCESSFUL_XSS = {}

    PAYLOADS_FILE = "xssPayloads.txt"

    MSG_VULN = _("Stored XSS vulnerability")

    def __init__(self, crawler, xml_report_generator, logger, attack_options):
        Attack.__init__(self, crawler, xml_report_generator, logger, attack_options)
        self.independant_payloads = self.payloads

    # permanent XSS
    def attack(self, get_resources, forms):
        """This method searches XSS which could be permanently stored in the web application"""
        for original_request in get_resources:
            # First we will crawl again each webpage to look for tainted value the mod_xss module may have injected.
            # So let's skip methods other than GET.
            if original_request.method != "GET":
                continue

            url = original_request.url
            target_req = web.Request(url)
            referer = original_request.referer
            headers = {}

            if referer:
                headers["referer"] = referer
            if self.verbose >= 1:
                print("[+] {}".format(url))

            try:
                response = self.crawler.send(target_req, headers=headers)
                data = response.content
            except Timeout:
                data = ""
            except OSError as exception:
                data = ""
                # TODO: those error messages are useless, don't give any valuable information
                print(_("error: {0} while attacking {1}").format(exception.strerror, url))
            except Exception as exception:
                print(_("error: {0} while attacking {1}").format(exception, url))
                continue

            # Should we look for taint codes sent with GET in the webpages?
            # Exploiting those may imply sending more GET requests
            if self.do_get == 1:
                # Search in the page source for every taint code used by mod_xss
                for taint in self.GET_XSS:
                    if taint in data:
                        # code found in the webpage !
                        code_url = self.GET_XSS[taint][0].url
                        page = self.GET_XSS[taint][0].path
                        parameter = self.GET_XSS[taint][1]

                        # Did mod_xss saw this as a reflected XSS ?
                        if taint in self.SUCCESSFUL_XSS:
                            # Yes, it means XSS payloads were injected, not just tainted code.

                            if self.valid_xss(data, taint, self.SUCCESSFUL_XSS[taint]):
                                # If we can find the payload again, this is in fact a stored XSS
                                evil_request = web.Request(code_url.replace(taint, self.SUCCESSFUL_XSS[taint]))

                                self.log_red("---")
                                if parameter == "QUERY_STRING":
                                    injection_msg = Vulnerability.MSG_QS_INJECT
                                else:
                                    injection_msg = Vulnerability.MSG_PARAM_INJECT

                                self.log_red(injection_msg, self.MSG_VULN, page, parameter)
                                self.log_red(Vulnerability.MSG_EVIL_URL, code_url)
                                self.log_red("---")

                                self.add_vuln(
                                    request_id=original_request.path_id,
                                    category=Vulnerability.XSS,
                                    level=Vulnerability.HIGH_LEVEL,
                                    request=evil_request,
                                    parameter=parameter,
                                    info=_("Found permanent XSS in {0}"
                                           " with {1}").format(page, escape(evil_request.url))
                                )
                                # we reported the vuln, now search another code
                                continue

                        # Ok the content is stored, but will we be able to inject javascript?
                        else:
                            timeouted = False
                            saw_internal_error = False

                            for xss, flags in self.independant_payloads:
                                payload = xss.replace("__XSS__", taint)
                                evil_request = web.Request(code_url.replace(taint, payload))
                                try:
                                    http_code = self.crawler.send(evil_request).status
                                    dat = self.crawler.send(target_req).content
                                except ReadTimeout:
                                    dat = ""
                                    if timeouted:
                                        continue

                                    self.log_orange("---")
                                    self.log_orange(Anomaly.MSG_TIMEOUT, page)
                                    self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                                    self.log_orange(evil_request.http_repr())
                                    self.log_orange("---")

                                    self.add_anom(
                                        request_id=original_request.path_id,
                                        category=Anomaly.RES_CONSUMPTION,
                                        level=Anomaly.MEDIUM_LEVEL,
                                        request=evil_request,
                                        parameter=parameter,
                                        info=Anomaly.MSG_PARAM_TIMEOUT.format(parameter)
                                    )
                                    timeouted = True

                                except Exception as exception:
                                    print(_('error: {0} while attacking {1}').format(exception, url))
                                    continue

                                if self.valid_xss(dat, taint, payload):
                                    # injection successful :)
                                    if parameter == "QUERY_STRING":
                                        injection_msg = Vulnerability.MSG_QS_INJECT
                                    else:
                                        injection_msg = Vulnerability.MSG_PARAM_INJECT

                                    self.log_red("---")
                                    self.log_red(
                                        injection_msg,
                                        self.MSG_VULN,
                                        page,
                                        parameter
                                    )
                                    self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                                    self.log_red(evil_request.http_repr())
                                    self.log_red("---")

                                    self.add_vuln(
                                        request_id=original_request.path_id,
                                        category=Vulnerability.XSS,
                                        level=Vulnerability.HIGH_LEVEL,
                                        request=evil_request,
                                        parameter=parameter,
                                        info=_("Found permanent XSS in {0}"
                                               " with {1}").format(url, escape(evil_request.url))
                                    )
                                    # look for another code in the webpage
                                    break
                                elif http_code == 500 and not saw_internal_error:
                                    self.add_anom(
                                        request_id=original_request.path_id,
                                        category=Anomaly.ERROR_500,
                                        level=Anomaly.HIGH_LEVEL,
                                        request=evil_request,
                                        parameter=parameter,
                                        info=Anomaly.MSG_PARAM_500.format(parameter)
                                    )

                                    self.log_orange("---")
                                    self.log_orange(Anomaly.MSG_500, page)
                                    self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                                    self.log_orange(evil_request.http_repr())
                                    self.log_orange("---")
                                    saw_internal_error = True

            # Should we look for taint codes sent with POST in the webpages?
            # Exploiting those may probably imply sending more POST requests
            if self.do_post == 1:
                for taint in self.POST_XSS:
                    if taint in data:
                        # Code found in the webpage!
                        # Did mod_xss saw this as a reflected XSS ?
                        if taint in self.SUCCESSFUL_XSS:
                            if self.valid_xss(data, taint, self.SUCCESSFUL_XSS[taint]):

                                code_req = self.POST_XSS[taint][0]
                                get_params = code_req.get_params
                                post_params = code_req.post_params
                                file_params = code_req.file_params
                                referer = code_req.referer

                                for params_list in [get_params, post_params, file_params]:
                                    for i in range(len(params_list)):
                                        parameter, value = params_list[i]
                                        parameter = quote(parameter)
                                        if value == taint:
                                            if params_list is file_params:
                                                params_list[i][1][0] = self.SUCCESSFUL_XSS[taint]
                                            else:
                                                params_list[i][1] = self.SUCCESSFUL_XSS[taint]

                                            # we found the xss payload again -> stored xss vuln
                                            evil_request = web.Request(
                                                code_req.path,
                                                method="POST",
                                                get_params=get_params,
                                                post_params=post_params,
                                                file_params=file_params,
                                                referer=referer
                                            )

                                            self.add_vuln(
                                                request_id=original_request.path_id,
                                                category=Vulnerability.XSS,
                                                level=Vulnerability.HIGH_LEVEL,
                                                request=evil_request,
                                                parameter=parameter,
                                                info=_("Found permanent XSS attacked by {0} with fields"
                                                       " {1}").format(
                                                    evil_request.url,
                                                    encode(post_params)
                                                )
                                            )

                                            self.log_red("---")
                                            self.log_red(
                                                Vulnerability.MSG_PARAM_INJECT,
                                                self.MSG_VULN,
                                                evil_request.path,
                                                parameter
                                            )
                                            self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                                            self.log_red(evil_request.http_repr())
                                            self.log_red("---")
                                            # search for the next code in the webpage
                                    continue

                        # we found the code but no attack was made
                        # let's try to break in
                        else:
                            code_req = self.POST_XSS[taint][0]
                            get_params = code_req.get_params
                            post_params = code_req.post_params
                            file_params = code_req.file_params
                            referer = code_req.referer

                            for params_list in [get_params, post_params, file_params]:
                                for i in range(len(params_list)):
                                    parameter, value = params_list[i]
                                    parameter = quote(parameter)
                                    if value == taint:
                                        timeouted = False
                                        saw_internal_error = False
                                        for xss, flags in self.independant_payloads:
                                            payload = xss.replace("__XSS__", taint)

                                            if params_list is file_params:
                                                params_list[i][1][0] = payload
                                            else:
                                                params_list[i][1] = payload

                                            try:
                                                evil_request = web.Request(
                                                    code_req.path,
                                                    method=code_req.method,
                                                    get_params=get_params,
                                                    post_params=post_params,
                                                    file_params=file_params,
                                                    referer=referer
                                                )
                                                http_code = self.crawler.send(evil_request).status
                                                dat = self.crawler.send(target_req).content
                                            except ReadTimeout:
                                                dat = ""
                                                if timeouted:
                                                    continue

                                                self.log_orange("---")
                                                self.log_orange(Anomaly.MSG_TIMEOUT, evil_request.url)
                                                self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                                                self.log_orange(evil_request.http_repr())
                                                self.log_orange("---")

                                                self.add_anom(
                                                    request_id=original_request.path_id,
                                                    category=Anomaly.RES_CONSUMPTION,
                                                    level=Anomaly.MEDIUM_LEVEL,
                                                    request=evil_request,
                                                    parameter=parameter,
                                                    info=Anomaly.MSG_PARAM_TIMEOUT.format(parameter)
                                                )
                                                timeouted = True
                                            except Exception as exception:
                                                print(_("error: {0} while attacking {1}").format(exception, url))
                                                continue

                                            if self.valid_xss(dat, taint, payload):
                                                self.add_vuln(
                                                    request_id=original_request.path_id,
                                                    category=Vulnerability.XSS,
                                                    level=Vulnerability.HIGH_LEVEL,
                                                    request=evil_request,
                                                    parameter=parameter,
                                                    info=_("Found permanent XSS attacked by {0} with fields"
                                                           " {1}").format(
                                                        evil_request.url,
                                                        encode(post_params)
                                                    )
                                                )

                                                self.log_red("---")
                                                self.log_red(
                                                    Vulnerability.MSG_PARAM_INJECT,
                                                    self.MSG_VULN,
                                                    evil_request.path,
                                                    parameter
                                                )
                                                self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                                                self.log_red(evil_request.http_repr())
                                                self.log_red("---")
                                                break
                                            elif http_code == 500 and not saw_internal_error:
                                                self.add_anom(
                                                    request_id=original_request.path_id,
                                                    category=Anomaly.ERROR_500,
                                                    level=Anomaly.HIGH_LEVEL,
                                                    request=evil_request,
                                                    parameter=parameter,
                                                    info=Anomaly.MSG_PARAM_500.format(parameter)
                                                )

                                                self.log_orange("---")
                                                self.log_orange(Anomaly.MSG_500, evil_request.url)
                                                self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                                                self.log_orange(evil_request.http_repr())
                                                self.log_orange("---")
                                                saw_internal_error = True

            yield original_request

    # check whether our JS payload is injected in the webpage
    @staticmethod
    def valid_xss(page, code, payload):
        if page is None or page == "":
            return False
        if payload.lower() in page.lower():
            return True
        return False

    @staticmethod
    def valid_content_type(http_res):
        """Check whether the returned content-type header allow javascript evaluation."""
        if "content-type" not in http_res.headers:
            return True
        if "text/html" in http_res.headers["content-type"]:
            return True
        return False

    def load_require(self, dependancies: list = None):
        if dependancies:
            for module in dependancies:
                if module.name == "xss":
                    self.GET_XSS = module.GET_XSS
                    self.POST_XSS = module.POST_XSS
                    self.SUCCESSFUL_XSS = module.SUCCESSFUL_XSS
