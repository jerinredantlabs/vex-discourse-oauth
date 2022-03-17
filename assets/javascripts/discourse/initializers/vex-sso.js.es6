import { withPluginApi } from "discourse/lib/plugin-api";
import logout from "discourse/lib/logout";

const REDIRECT_URL = "https://pd.vex.com";

function myLogout(currentUser, noRetry) {
  if (currentUser) {
    currentUser.destroySession()
      .then((response) => logout({ redirect: REDIRECT_URL }))
      .catch((err) => {
        if (!noRetry) {
          myLogout(currentUser, true);
        }
      });
  }
}

export default {
  name: "vex-sso",

  initialize() {
    withPluginApi("0.11.7", (api) => {
      const currentUser = api.getCurrentUser();
      if (currentUser) {
        console.log("checking user groups");
        const groups = currentUser.groups.map(group => group.name);
        const isAdmin = currentUser.admin;
        const isStaff = currentUser.staff;
        const hasVex = groups.some((group) => group.startsWith("vex"));
        console.log(`current user is admin: ${isAdmin} is staff: ${isStaff} is licensed: ${hasVex}`);
        const hasAccess = isAdmin || isStaff || hasVex;
        if (!hasAccess) {
          console.warn("current user does not have access. redirect to community site");
          myLogout(currentUser);
        }
      } else {
        console.warn("no user logged in");
      }
      // window.dapi = api
    });
  },
};
