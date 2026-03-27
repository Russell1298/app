import { TouchableOpacity, Text, ActivityIndicator } from "react-native";
import { Colors } from "@/constants/Colors";

interface ButtonProps {
  title: string;
  onPress: () => void;
  loading?: boolean;
  variant?: "primary" | "outline";
  disabled?: boolean;
}

export function Button({
  title,
  onPress,
  loading = false,
  variant = "primary",
  disabled = false
}: ButtonProps) {
  const isPrimary = variant === "primary";
  return (
    <TouchableOpacity
      onPress={onPress}
      disabled={disabled || loading}
      className={`rounded-xl py-4 items-center justify-center flex-row ${
        isPrimary ? "bg-primary" : "border-2 border-primary bg-transparent"
      } ${disabled || loading ? "opacity-60" : ""}`}
    >
      {loading ? (
        <ActivityIndicator
          color={isPrimary ? "white" : Colors.primary}
          size="small"
        />
      ) : (
        <Text
          className={`text-base font-bold ${
            isPrimary ? "text-white" : "text-primary"
          }`}
        >
          {title}
        </Text>
      )}
    </TouchableOpacity>
  );
}
