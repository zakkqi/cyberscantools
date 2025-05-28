// frontend/src/store/index.js
import { configureStore } from '@reduxjs/toolkit';
import authReducer from './authSlice';
import scanReducer from './scanSlice';

export const store = configureStore({
    reducer: {
        auth: authReducer,
        scan: scanReducer
    }
});

export default store;