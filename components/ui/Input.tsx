import { View, Text, TextInput, TextInputProps } from "react-native";
import { ReactNode } from "react";

interface InputProps extends TextInputProps {
  label?: string;
  icon?: ReactNode;
}

export function Input({ label, icon, style, ...props }: InputProps) {
  return (
    <View className="mb-4">
      {label && (
        <Text className="text-gray-600 text-sm font-medium mb-1.5">
          {label}
        </Text>
      )}
      <View className="flex-row items-center border border-gray-200 rounded-xl px-3 bg-gray-50">
        {icon && <View className="mr-2">{icon}</View>}
        <TextInput
          className="flex-1 text-slate-dark text-sm py-3.5"
          placeholderTextColor="#9ca3af"
          {...props}
        />
      </View>
    </View>
  );
}
