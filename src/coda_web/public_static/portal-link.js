// Classic script shared by the customer and internal static trees. It publishes one global so
// finding cards build account overview or Data Explorer links from the same route contract.
(function () {
  "use strict";

  var ACCOUNT_RESOURCE_ID_RE =
    /\/subscriptions\/([^/]+)\/resourceGroups\/([^/]+)\/providers\/Microsoft\.DocumentDB\/databaseAccounts\/([^/]+)/i;

  function parseAccountResourceId(accountResourceId) {
    var match = ACCOUNT_RESOURCE_ID_RE.exec(String(accountResourceId || ""));
    if (!match) return null;
    return { subscriptionId: match[1], resourceGroup: match[2], accountName: match[3] };
  }

  function parseDiscreteContext(context) {
    if (!context || typeof context !== "object") return null;
    var subscriptionId = context.subscriptionId || context.subscription_id || context.subscription;
    var resourceGroup = context.resourceGroup || context.resource_group;
    var accountName = context.accountName || context.account_name || context.account;
    if (!subscriptionId || !resourceGroup || !accountName) return null;
    return {
      subscriptionId: String(subscriptionId),
      resourceGroup: String(resourceGroup),
      accountName: String(accountName),
    };
  }

  function substitute(template, placeholder, value) {
    return template.split(placeholder).join(value);
  }

  function buildUrl(template, accountResourceId, context) {
    var parsed = parseAccountResourceId(accountResourceId)
      || parseDiscreteContext(context)
      || parseDiscreteContext(accountResourceId);
    if (!parsed) return null;
    var url = template;
    url = substitute(url, "{subscription}", encodeURIComponent(parsed.subscriptionId));
    url = substitute(url, "{resourceGroup}", encodeURIComponent(parsed.resourceGroup));
    url = substitute(url, "{account}", encodeURIComponent(parsed.accountName));
    return url;
  }

  var CODA_PORTAL_LINK = {
    PORTAL_ACCOUNT_URL_TEMPLATE: "https://portal.azure.com/#resource/subscriptions/{subscription}/resourceGroups/{resourceGroup}/providers/Microsoft.DocumentDB/databaseAccounts/{account}",
    PORTAL_DATA_EXPLORER_URL_TEMPLATE: "https://portal.azure.com/#resource/subscriptions/{subscription}/resourceGroups/{resourceGroup}/providers/Microsoft.DocumentDB/databaseAccounts/{account}/DataExplorerBlade",
    buildAccountUrl: function (accountResourceId, context) {
      return buildUrl(CODA_PORTAL_LINK.PORTAL_ACCOUNT_URL_TEMPLATE, accountResourceId, context);
    },
    buildDataExplorerUrl: function (accountResourceId, context) {
      return buildUrl(CODA_PORTAL_LINK.PORTAL_DATA_EXPLORER_URL_TEMPLATE, accountResourceId, context);
    },
  };

  window.CODA_PORTAL_LINK = CODA_PORTAL_LINK;
})();
