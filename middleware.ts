import { clerkMiddleware, clerkClient,getAuth } from "@clerk/nextjs/server";
import { NextResponse } from "next/server";

const publicRoutes = ["/", "/api/webhook/register", "/sign-in", "/sign-up"];

export default clerkMiddleware(async (req) => {
  const { userId } = getAuth(req);

  const url = req.nextUrl.clone();

  // Redirect unauthenticated users trying to access protected routes
  if (!userId && !publicRoutes.includes(url.pathname)) {
    url.pathname = "/sign-in";
    return NextResponse.redirect(url);
  }

  if (userId) {
    try {
      const user = await clerkClient.users.getUser(userId); // Fetch user data from Clerk
      const role = user.publicMetadata.role as string | undefined;

      // Admin role redirection logic
      if (role === "admin" && url.pathname === "/dashboard") {
        url.pathname = "/admin/dashboard";
        return NextResponse.redirect(url);
      }

      // Prevent non-admin users from accessing admin routes
      if (role !== "admin" && url.pathname.startsWith("/admin")) {
        url.pathname = "/dashboard";
        return NextResponse.redirect(url);
      }

      // Redirect authenticated users trying to access public routes
      if (publicRoutes.includes(url.pathname)) {
        url.pathname = role === "admin" ? "/admin/dashboard" : "/dashboard";
        return NextResponse.redirect(url);
      }
    } catch (error) {
      console.error("Error fetching user data from Clerk:", error);
      url.pathname = "/error";
      return NextResponse.redirect(url);
    }
  }

  // Continue processing the request
  return NextResponse.next();
});

export const config = {
  matcher: ["/((?!.+\\.[\\w]+$|_next).*)", "/", "/(api|trpc)(.*)"],
};
