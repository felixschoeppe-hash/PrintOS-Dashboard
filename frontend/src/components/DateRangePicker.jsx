import { useState } from "react";
import { format, subDays, subMonths, subYears, startOfDay, endOfDay, startOfMonth, endOfMonth, startOfYear, endOfYear } from "date-fns";
import { de } from "date-fns/locale";
import { CalendarIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const PRESETS = {
  "today": { label: "Heute", getRange: () => ({ from: startOfDay(new Date()), to: endOfDay(new Date()) }) },
  "yesterday": { label: "Gestern", getRange: () => ({ from: startOfDay(subDays(new Date(), 1)), to: endOfDay(subDays(new Date(), 1)) }) },
  "last7days": { label: "Letzte 7 Tage", getRange: () => ({ from: startOfDay(subDays(new Date(), 7)), to: endOfDay(new Date()) }) },
  "last30days": { label: "Letzte 30 Tage", getRange: () => ({ from: startOfDay(subDays(new Date(), 30)), to: endOfDay(new Date()) }) },
  "thisMonth": { label: "Dieser Monat", getRange: () => ({ from: startOfMonth(new Date()), to: endOfMonth(new Date()) }) },
  "lastMonth": { label: "Letzter Monat", getRange: () => ({ from: startOfMonth(subMonths(new Date(), 1)), to: endOfMonth(subMonths(new Date(), 1)) }) },
  "thisYear": { label: "Dieses Jahr", getRange: () => ({ from: startOfYear(new Date()), to: endOfYear(new Date()) }) },
  "lastYear": { label: "Letztes Jahr", getRange: () => ({ from: startOfYear(subYears(new Date(), 1)), to: endOfYear(subYears(new Date(), 1)) }) },
  "all": { label: "Alle Daten", getRange: () => ({ from: null, to: null }) },
};

export function DateRangePicker({ dateRange, onDateRangeChange, className }) {
  const [isOpen, setIsOpen] = useState(false);
  const [preset, setPreset] = useState("all");

  const handlePresetChange = (value) => {
    setPreset(value);
    const range = PRESETS[value].getRange();
    onDateRangeChange(range);
  };

  const handleCalendarSelect = (range) => {
    if (range?.from) {
      onDateRangeChange({
        from: startOfDay(range.from),
        to: range.to ? endOfDay(range.to) : endOfDay(range.from)
      });
      setPreset("custom");
    }
  };

  const formatDateRange = () => {
    if (!dateRange?.from && !dateRange?.to) {
      return "Alle Daten";
    }
    if (dateRange?.from && dateRange?.to) {
      return `${format(dateRange.from, "dd.MM.yyyy", { locale: de })} - ${format(dateRange.to, "dd.MM.yyyy", { locale: de })}`;
    }
    if (dateRange?.from) {
      return format(dateRange.from, "dd.MM.yyyy", { locale: de });
    }
    return "Zeitraum wählen";
  };

  return (
    <div className={cn("flex items-center gap-2", className)}>
      {/* Preset Selector */}
      <Select value={preset} onValueChange={handlePresetChange}>
        <SelectTrigger 
          className="w-[150px] bg-slate-800 border-slate-700 text-white"
          data-testid="date-preset-selector"
        >
          <SelectValue placeholder="Zeitraum" />
        </SelectTrigger>
        <SelectContent className="bg-slate-800 border-slate-700">
          {Object.entries(PRESETS).map(([key, { label }]) => (
            <SelectItem 
              key={key} 
              value={key}
              className="text-white hover:bg-slate-700 focus:bg-slate-700"
            >
              {label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {/* Calendar Picker */}
      <Popover open={isOpen} onOpenChange={setIsOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="outline"
            className={cn(
              "w-[240px] justify-start text-left font-normal bg-slate-800 border-slate-700 text-white hover:bg-slate-700",
              !dateRange?.from && "text-slate-400"
            )}
            data-testid="date-range-picker"
          >
            <CalendarIcon className="mr-2 h-4 w-4" />
            {formatDateRange()}
          </Button>
        </PopoverTrigger>
        <PopoverContent 
          className="w-auto p-0 bg-slate-900 border-slate-700" 
          align="start"
        >
          <Calendar
            initialFocus
            mode="range"
            defaultMonth={dateRange?.from || new Date()}
            selected={{ from: dateRange?.from, to: dateRange?.to }}
            onSelect={handleCalendarSelect}
            numberOfMonths={2}
            locale={de}
            className="bg-slate-900 text-white"
            classNames={{
              months: "flex flex-col sm:flex-row space-y-4 sm:space-x-4 sm:space-y-0",
              month: "space-y-4",
              caption: "flex justify-center pt-1 relative items-center text-white",
              caption_label: "text-sm font-medium text-white",
              nav: "space-x-1 flex items-center",
              nav_button: "h-7 w-7 bg-slate-800 p-0 opacity-70 hover:opacity-100 border border-slate-700 rounded text-white hover:bg-slate-700",
              nav_button_previous: "absolute left-1",
              nav_button_next: "absolute right-1",
              table: "w-full border-collapse space-y-1",
              head_row: "flex",
              head_cell: "text-slate-400 rounded-md w-9 font-normal text-[0.8rem]",
              row: "flex w-full mt-2",
              cell: "relative p-0 text-center text-sm focus-within:relative focus-within:z-20 [&:has([aria-selected])]:bg-cyan-500/20 rounded",
              day: "h-9 w-9 p-0 font-normal text-white hover:bg-slate-700 rounded aria-selected:opacity-100",
              day_range_start: "day-range-start bg-cyan-500 text-slate-950 hover:bg-cyan-400",
              day_range_end: "day-range-end bg-cyan-500 text-slate-950 hover:bg-cyan-400",
              day_selected: "bg-cyan-500 text-slate-950 hover:bg-cyan-400 focus:bg-cyan-500",
              day_today: "bg-slate-700 text-cyan-400",
              day_outside: "text-slate-600 opacity-50",
              day_disabled: "text-slate-600 opacity-30",
              day_range_middle: "aria-selected:bg-cyan-500/20 aria-selected:text-white",
              day_hidden: "invisible",
            }}
          />
        </PopoverContent>
      </Popover>
    </div>
  );
}
