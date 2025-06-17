
import { useState } from "react";
import { useForm } from "react-hook-form";
import { format } from "date-fns";
import { CalendarIcon, Info } from "lucide-react";
import { Calendar } from "@/components/ui/calendar";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Textarea } from "@/components/ui/textarea";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";

const formSchema = z.object({
  walletAddress: z
    .string()
    .min(1, "Wallet address is required")
    .regex(/^0x[a-fA-F0-9]{40}$/, "Please enter a valid ETH address format"),
  incidentDate: z.date().optional(),
  description: z.string().min(1, "Please describe what happened"),
  knownScamURL: z.string().optional(),
  scammerContact: z.string().optional(),
  contactEmail: z.string().email("Please enter a valid email").optional(),
  optInToFollowUp: z.boolean().optional(),
  consent: z.boolean().refine(val => val === true, {
    message: "You must agree to continue",
  }),
});

export type WalletFormData = z.infer<typeof formSchema>;

interface WalletCheckFormProps {
  onFormSubmit: (data: WalletFormData) => void;
}

export function WalletCheckForm({ onFormSubmit }: WalletCheckFormProps) {
  const [showEmailField, setShowEmailField] = useState(false);

  const form = useForm<WalletFormData>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      walletAddress: "",
      description: "",
      knownScamURL: "",
      scammerContact: "",
      contactEmail: "",
      optInToFollowUp: false,
      consent: false,
    },
  });

  function onSubmit(data: WalletFormData) {
    toast.info("Form submitted, analyzing your wallet...");
    console.log("Form data:", data);
    
    // Here you would typically make an API call
    // For the MVP, we'll just pass the data to the parent component
    onFormSubmit(data);
  }

  return (
    <div className="bg-hibr-muted p-6 rounded-lg neo-brutalism">
      <h2 className="text-2xl font-bold mb-6 text-hibr-accent">
        Wallet Check Form
      </h2>

      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
          <FormField
            control={form.control}
            name="walletAddress"
            render={({ field }) => (
              <FormItem>
                <FormLabel className="flex items-center gap-2">
                  Wallet Address
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Info className="h-4 w-4 text-hibr-accent cursor-help" />
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>Enter your Ethereum wallet address (0x...)</p>
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                </FormLabel>
                <FormControl>
                  <Input
                    placeholder="0x..."
                    className="cyber-input"
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="incidentDate"
            render={({ field }) => (
              <FormItem className="flex flex-col">
                <FormLabel>Incident Date (approximate)</FormLabel>
                <Popover>
                  <PopoverTrigger asChild>
                    <FormControl>
                      <Button
                        variant={"outline"}
                        className={cn(
                          "w-full pl-3 text-left font-normal",
                          !field.value && "text-muted-foreground"
                        )}
                      >
                        {field.value ? (
                          format(field.value, "PPP")
                        ) : (
                          <span>Pick a date</span>
                        )}
                        <CalendarIcon className="ml-auto h-4 w-4 opacity-50" />
                      </Button>
                    </FormControl>
                  </PopoverTrigger>
                  <PopoverContent className="w-auto p-0" align="start">
                    <Calendar
                      mode="single"
                      selected={field.value}
                      onSelect={field.onChange}
                      disabled={(date) => date > new Date()}
                      initialFocus
                      className="p-3 pointer-events-auto"
                    />
                  </PopoverContent>
                </Popover>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="description"
            render={({ field }) => (
              <FormItem>
                <FormLabel>What happened?</FormLabel>
                <FormControl>
                  <Textarea
                    placeholder="Describe the incident..."
                    className="cyber-input"
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="knownScamURL"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Known Scam URL (optional)</FormLabel>
                <FormControl>
                  <Input
                    placeholder="https://..."
                    className="cyber-input"
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="scammerContact"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  Scammer Contact Information (optional)
                </FormLabel>
                <FormControl>
                  <Input
                    placeholder="Social accounts, email, etc."
                    className="cyber-input"
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="optInToFollowUp"
            render={({ field }) => (
              <FormItem className="flex flex-row items-start space-x-3 space-y-0">
                <FormControl>
                  <Checkbox
                    checked={field.value}
                    onCheckedChange={(checked) => {
                      field.onChange(checked);
                      setShowEmailField(!!checked);
                    }}
                    className="data-[state=checked]:bg-hibr-accent data-[state=checked]:border-hibr-accent"
                  />
                </FormControl>
                <FormLabel className="font-normal">
                  Opt in to follow-up (we'll email you with results)
                </FormLabel>
              </FormItem>
            )}
          />

          {showEmailField && (
            <FormField
              control={form.control}
              name="contactEmail"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Contact Email</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="your@email.com"
                      className="cyber-input"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          )}

          <FormField
            control={form.control}
            name="consent"
            render={({ field }) => (
              <FormItem className="flex flex-row items-start space-x-3 space-y-0">
                <FormControl>
                  <Checkbox
                    checked={field.value}
                    onCheckedChange={field.onChange}
                    className="data-[state=checked]:bg-hibr-accent data-[state=checked]:border-hibr-accent"
                  />
                </FormControl>
                <FormLabel className="font-normal">
                  I understand that this tool uses local AI and is for educational
                  purposes only.
                </FormLabel>
              </FormItem>
            )}
          />

          <Button 
            type="submit" 
            className="w-full neo-brutalism bg-hibr-accent text-black hover:bg-hibr-secondary hover:shadow-[4px_4px_0px_0px_rgba(255,52,179,0.8)]"
          >
            Check My Wallet
          </Button>
        </form>
      </Form>
    </div>
  );
}
