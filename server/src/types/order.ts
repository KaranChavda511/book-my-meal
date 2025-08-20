export type OrderStatus = "pending" | "confirmed" | "preparing" | "out_for_delivery" | "delivered" | "cancelled";

export interface IOrder {
  id: string;
  customerId: string;
  restaurantId: string;
  items: {
    menuItemId: string;
    quantity: number;
  }[];
  totalAmount: number;
  status: OrderStatus;
  createdAt?: Date;
  updatedAt?: Date;
}
