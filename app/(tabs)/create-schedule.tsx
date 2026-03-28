import { useState } from "react";
import {
  View,
  Text,
  ScrollView,
  TouchableOpacity,
  Platform,
  Alert
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import DateTimePicker, {
  DateTimePickerEvent
} from "@react-native-community/datetimepicker";
import { Calendar, Clock, Tag, AlignLeft, CheckCircle2 } from "lucide-react-native";
import { Input } from "@/components/ui/Input";
import { Colors } from "@/constants/Colors";

const DURATION_OPTIONS = [
  "15 min",
  "30 min",
  "45 min",
  "1 hr",
  "1.5 hr",
  "2 hr"
];

const TYPE_OPTIONS = [
  { label: "One-time", color: "#0069ff" },
  { label: "Recurring", color: "#7c3aed" },
  { label: "Team", color: "#059669" }
];

export default function CreateScheduleScreen() {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [date, setDate] = useState(new Date());
  const [time, setTime] = useState(new Date());
  const [duration, setDuration] = useState("30 min");
  const [type, setType] = useState("One-time");
  const [showDatePicker, setShowDatePicker] = useState(false);
  const [showTimePicker, setShowTimePicker] = useState(false);
  const [loading, setLoading] = useState(false);

  const formatDate = (d: Date) =>
    d.toLocaleDateString("en-US", {
      weekday: "short",
      month: "short",
      day: "numeric",
      year: "numeric"
    });

  const formatTime = (d: Date) =>
    d.toLocaleTimeString("en-US", {
      hour: "numeric",
      minute: "2-digit",
      hour12: true
    });

  const onDateChange = (_: DateTimePickerEvent, selected?: Date) => {
    setShowDatePicker(Platform.OS === "ios");
    if (selected) setDate(selected);
  };

  const onTimeChange = (_: DateTimePickerEvent, selected?: Date) => {
    setShowTimePicker(Platform.OS === "ios");
    if (selected) setTime(selected);
  };

  const handleCreate = () => {
    if (!title.trim()) {
      Alert.alert("Required", "Please enter a schedule title.");
      return;
    }
    setLoading(true);
    setTimeout(() => {
      setLoading(false);
      Alert.alert("Schedule Created", `"${title}" has been added.`, [
        {
          text: "Done",
          onPress: () => {
            setTitle("");
            setDescription("");
            setDate(new Date());
            setTime(new Date());
            setDuration("30 min");
            setType("One-time");
          }
        }
      ]);
    }, 800);
  };

  const Section = ({ title: t, children }: { title: string; children: React.ReactNode }) => (
    <View
      style={{
        backgroundColor: "#fff",
        borderRadius: 16,
        padding: 16,
        marginBottom: 12,
        elevation: 1,
        shadowColor: "#000",
        shadowOpacity: 0.04,
        shadowRadius: 6,
        borderWidth: 1,
        borderColor: "#f1f5f9"
      }}
    >
      <Text
        style={{
          fontSize: 11,
          fontWeight: "700",
          color: "#9ca3af",
          textTransform: "uppercase",
          letterSpacing: 1,
          marginBottom: 14
        }}
      >
        {t}
      </Text>
      {children}
    </View>
  );

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: "#f3f5f9" }} edges={["top"]}>
      {/* Header */}
      <View
        style={{
          backgroundColor: "#fff",
          paddingHorizontal: 20,
          paddingVertical: 16,
          borderBottomWidth: 1,
          borderBottomColor: "#f1f5f9"
        }}
      >
        <Text style={{ fontSize: 22, fontWeight: "800", color: "#031b4e", letterSpacing: -0.4 }}>
          New Schedule
        </Text>
        <Text style={{ fontSize: 12, color: "#6b7280", marginTop: 1 }}>
          Fill in the details below
        </Text>
      </View>

      <ScrollView
        style={{ flex: 1 }}
        contentContainerStyle={{ padding: 16 }}
        keyboardShouldPersistTaps="handled"
        showsVerticalScrollIndicator={false}
      >
        {/* Type selector */}
        <Section title="Schedule Type">
          <View style={{ flexDirection: "row", gap: 8 }}>
            {TYPE_OPTIONS.map((opt) => {
              const selected = type === opt.label;
              return (
                <TouchableOpacity
                  key={opt.label}
                  onPress={() => setType(opt.label)}
                  style={{
                    flex: 1,
                    paddingVertical: 10,
                    borderRadius: 10,
                    alignItems: "center",
                    backgroundColor: selected ? opt.color : "#f3f5f9",
                    borderWidth: selected ? 0 : 1,
                    borderColor: "#e5e7eb"
                  }}
                >
                  <Text
                    style={{
                      fontSize: 13,
                      fontWeight: "700",
                      color: selected ? "#fff" : "#6b7280"
                    }}
                  >
                    {opt.label}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </View>
        </Section>

        {/* Details */}
        <Section title="Details">
          <Input
            label="Title"
            placeholder="e.g. Team Standup"
            value={title}
            onChangeText={setTitle}
            icon={<Tag color="#6b7280" size={16} />}
          />
          <Input
            label="Description"
            placeholder="Optional notes or agenda..."
            value={description}
            onChangeText={setDescription}
            multiline
            numberOfLines={3}
            textAlignVertical="top"
            icon={<AlignLeft color="#6b7280" size={16} />}
          />
        </Section>

        {/* Date & Time */}
        <Section title="Date & Time">
          <TouchableOpacity
            onPress={() => setShowDatePicker(true)}
            style={{
              flexDirection: "row",
              alignItems: "center",
              backgroundColor: "#f3f5f9",
              borderRadius: 10,
              paddingHorizontal: 14,
              paddingVertical: 13,
              marginBottom: 10,
              borderWidth: 1,
              borderColor: "#e5e7eb"
            }}
          >
            <Calendar color="#0069ff" size={16} />
            <Text
              style={{ marginLeft: 10, fontSize: 14, fontWeight: "600", color: "#031b4e" }}
            >
              {formatDate(date)}
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            onPress={() => setShowTimePicker(true)}
            style={{
              flexDirection: "row",
              alignItems: "center",
              backgroundColor: "#f3f5f9",
              borderRadius: 10,
              paddingHorizontal: 14,
              paddingVertical: 13,
              borderWidth: 1,
              borderColor: "#e5e7eb"
            }}
          >
            <Clock color="#0069ff" size={16} />
            <Text
              style={{ marginLeft: 10, fontSize: 14, fontWeight: "600", color: "#031b4e" }}
            >
              {formatTime(time)}
            </Text>
          </TouchableOpacity>

          {showDatePicker && (
            <DateTimePicker
              value={date}
              mode="date"
              display={Platform.OS === "ios" ? "spinner" : "default"}
              onChange={onDateChange}
              minimumDate={new Date()}
            />
          )}
          {showTimePicker && (
            <DateTimePicker
              value={time}
              mode="time"
              display={Platform.OS === "ios" ? "spinner" : "default"}
              onChange={onTimeChange}
            />
          )}
        </Section>

        {/* Duration */}
        <Section title="Duration">
          <View style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }}>
            {DURATION_OPTIONS.map((opt) => {
              const selected = duration === opt;
              return (
                <TouchableOpacity
                  key={opt}
                  onPress={() => setDuration(opt)}
                  style={{
                    paddingHorizontal: 16,
                    paddingVertical: 9,
                    borderRadius: 20,
                    backgroundColor: selected ? "#0069ff" : "#f3f5f9",
                    borderWidth: 1,
                    borderColor: selected ? "#0069ff" : "#e5e7eb"
                  }}
                >
                  <Text
                    style={{
                      fontSize: 13,
                      fontWeight: "700",
                      color: selected ? "#fff" : "#6b7280"
                    }}
                  >
                    {opt}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </View>
        </Section>

        {/* Submit */}
        <TouchableOpacity
          onPress={handleCreate}
          disabled={loading}
          style={{
            backgroundColor: "#0069ff",
            borderRadius: 14,
            paddingVertical: 16,
            flexDirection: "row",
            alignItems: "center",
            justifyContent: "center",
            gap: 8,
            marginTop: 4,
            opacity: loading ? 0.7 : 1,
            elevation: 3,
            shadowColor: "#0069ff",
            shadowOpacity: 0.3,
            shadowRadius: 8
          }}
        >
          <CheckCircle2 color="#fff" size={18} />
          <Text style={{ color: "#fff", fontSize: 16, fontWeight: "700" }}>
            {loading ? "Creating…" : "Create Schedule"}
          </Text>
        </TouchableOpacity>

        <View style={{ height: 32 }} />
      </ScrollView>
    </SafeAreaView>
  );
}
