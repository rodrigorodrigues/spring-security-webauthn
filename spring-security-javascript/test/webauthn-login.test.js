/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

"use strict";

import { setupLogin } from "../lib/webauthn-login.js";
import webauthn from "../lib/webauthn-core.js";
import { assert, fake, match, stub } from "sinon";

describe("webauthn-login", () => {
  describe("bootstrap", () => {
    let authenticateStub;
    let isConditionalMediationAvailableStub;
    let signinButton;

    beforeEach(() => {
      isConditionalMediationAvailableStub = stub(webauthn, "isConditionalMediationAvailable").resolves(false);
      authenticateStub = stub(webauthn, "authenticate").resolves(undefined);
      signinButton = {
        addEventListener: fake(),
      };
    });

    afterEach(() => {
      authenticateStub.restore();
      isConditionalMediationAvailableStub.restore();
    });

    it("sets up a click event listener on the signin button", async () => {
      await setupLogin({}, "/some/path", signinButton);

      assert.calledOnceWithMatch(signinButton.addEventListener, "click", match.typeOf("function"));
    });

    it("uses conditional mediation when available", async () => {
      isConditionalMediationAvailableStub.resolves(true);

      const headers = { "x-header": "value" };
      const contextPath = "/some/path";

      await setupLogin(headers, contextPath, signinButton);

      assert.calledOnceWithExactly(authenticateStub, headers, contextPath, true);
    });

    it("does not call authenticate when conditional mediation is not available", async () => {
      isConditionalMediationAvailableStub.resolves(false);

      await setupLogin({}, "/", signinButton);

      assert.notCalled(authenticateStub);
    });

    it("calls authenticate when the signin button is clicked", async () => {
      isConditionalMediationAvailableStub.resolves(false);
      const headers = { "x-header": "value" };
      const contextPath = "/some/path";

      await setupLogin(headers, contextPath, signinButton);

      // Call the event listener
      await signinButton.addEventListener.firstCall.lastArg();

      assert.calledOnceWithExactly(authenticateStub, headers, contextPath, false);
    });
  });
});
