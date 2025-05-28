/* eslint-disable @typescript-eslint/no-explicit-any */
import React from "react";
import { useForm } from "react-hook-form";
import { yupResolver } from "@hookform/resolvers/yup";
import * as yup from "yup";

const validationSchema = yup.object().shape({
  fullName: yup.string().required("Full Name is required"),
  email: yup
    .string()
    .email("Invalid email address")
    .required("Email is required"),
  phone: yup.string().optional(),
  preferredContactMethod: yup
    .string()
    .required("Preferred Contact Method is required"),
  walletAddress: yup.string().required("Wallet Address is required"),
  walletType: yup.string().required("Wallet Type is required"),
  blockchains: yup.string().required("Blockchain(s) involved is required"),
  issueDate: yup
    .date()
    .required("Date you first noticed the issue is required"),
  lastSafeAccess: yup
    .date()
    .required("Approximate time of last known safe access is required"),
  incidentDescription: yup
    .string()
    .required("Incident description is required"),
  unauthorizedTransactions: yup.boolean().required("This field is required"),
  attackType: yup
    .array()
    .of(yup.string())
    .required("Please select at least one attack type"),
  sharedSeedPhrase: yup.string().required("This field is required"),
  revokedApprovals: yup.boolean().required("This field is required"),
  transferredFunds: yup.boolean().required("This field is required"),
  reportedElsewhere: yup.string().optional(),
  recoveryHelp: yup.string().required("This field is required"),
  relevantLinks: yup.string().optional(),
  otherNotes: yup.string().optional(),
});

const CompromisedWalletForm: React.FC = () => {
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm({
    resolver: yupResolver(validationSchema),
  });

  const onSubmit = (data: any) => {
    console.log("Form Data:", data);
  };

  return (
    <form
      onSubmit={handleSubmit(onSubmit)}
      className="max-w-4xl mx-auto p-8 bg-gray-800 text-gray-200 shadow-lg rounded-lg space-y-8"
    >
      <h1 className="text-3xl font-bold text-pink-500 text-center">
        Compromised Wallet Report Form
      </h1>

      {/* Section 1: Contact Information */}
      <fieldset className="space-y-6">
        <legend className="text-xl font-semibold text-gray-300">
          Contact Information
        </legend>
        <div>
          <label className="block text-sm font-medium text-gray-400">
            Full Name:
            <input
              {...register("fullName")}
              className="mt-2 block w-full bg-gray-700 border border-gray-600 rounded-md shadow-sm text-gray-200 focus:ring-pink-500 focus:border-pink-500"
            />
            {errors.fullName && (
              <p className="text-pink-500 text-sm mt-1">
                {errors.fullName.message}
              </p>
            )}
          </label>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-400">
            Email Address:
            <input
              type="email"
              {...register("email")}
              className="mt-2 block w-full bg-gray-700 border border-gray-600 rounded-md shadow-sm text-gray-200 focus:ring-pink-500 focus:border-pink-500"
            />
            {errors.email && (
              <p className="text-pink-500 text-sm mt-1">
                {errors.email.message}
              </p>
            )}
          </label>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-400">
            Phone Number (optional):
            <input
              type="tel"
              {...register("phone")}
              className="mt-2 block w-full bg-gray-700 border border-gray-600 rounded-md shadow-sm text-gray-200 focus:ring-pink-500 focus:border-pink-500"
            />
          </label>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-400">
            Preferred Contact Method:
            <select
              {...register("preferredContactMethod")}
              className="mt-2 block w-full bg-gray-700 border border-gray-600 rounded-md shadow-sm text-gray-200 focus:ring-pink-500 focus:border-pink-500"
            >
              <option value="">Select</option>
              <option value="email">Email</option>
              <option value="phone">Phone</option>
              <option value="other">Other</option>
            </select>
            {errors.preferredContactMethod && (
              <p className="text-pink-500 text-sm mt-1">
                {errors.preferredContactMethod.message}
              </p>
            )}
          </label>
        </div>
      </fieldset>

      {/* Section 2: Wallet Details */}
      <fieldset className="space-y-6">
        <legend className="text-xl font-semibold text-gray-300">
          Wallet Details
        </legend>
        <div>
          <label className="block text-sm font-medium text-gray-400">
            Wallet Address (Public Key):
            <input
              {...register("walletAddress")}
              className="mt-2 block w-full bg-gray-700 border border-gray-600 rounded-md shadow-sm text-gray-200 focus:ring-pink-500 focus:border-pink-500"
            />
            {errors.walletAddress && (
              <p className="text-pink-500 text-sm mt-1">
                {errors.walletAddress.message}
              </p>
            )}
          </label>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-400">
            Wallet Type/Provider:
            <input
              {...register("walletType")}
              className="mt-2 block w-full bg-gray-700 border border-gray-600 rounded-md shadow-sm text-gray-200 focus:ring-pink-500 focus:border-pink-500"
            />
            {errors.walletType && (
              <p className="text-pink-500 text-sm mt-1">
                {errors.walletType.message}
              </p>
            )}
          </label>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-400">
            Blockchain(s) Involved:
            <input
              {...register("blockchains")}
              className="mt-2 block w-full bg-gray-700 border border-gray-600 rounded-md shadow-sm text-gray-200 focus:ring-pink-500 focus:border-pink-500"
            />
            {errors.blockchains && (
              <p className="text-pink-500 text-sm mt-1">
                {errors.blockchains.message}
              </p>
            )}
          </label>
        </div>
      </fieldset>

      {/* Section 3: Incident Description */}
      <fieldset className="space-y-6">
        <legend className="text-xl font-semibold text-gray-300">
          Incident Description
        </legend>
        <div>
          <label className="block text-sm font-medium text-gray-400">
            Describe What Happened:
            <textarea
              {...register("incidentDescription")}
              className="mt-2 block w-full bg-gray-700 border border-gray-600 rounded-md shadow-sm text-gray-200 focus:ring-pink-500 focus:border-pink-500"
            />
            {errors.incidentDescription && (
              <p className="text-pink-500 text-sm mt-1">
                {errors.incidentDescription.message}
              </p>
            )}
          </label>
        </div>
      </fieldset>

      <button
        type="submit"
        className="w-full py-3 px-6 bg-pink-500 text-white font-semibold rounded-lg shadow-md hover:bg-pink-600 focus:outline-none focus:ring-2 focus:ring-pink-500"
      >
        Submit
      </button>
    </form>
  );
};

export default CompromisedWalletForm;
