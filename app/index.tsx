import { Redirect } from "expo-router";

export default function Index() {
  // Default entry — send to sign-in
  return <Redirect href="/(auth)/sign-in" />;
}
